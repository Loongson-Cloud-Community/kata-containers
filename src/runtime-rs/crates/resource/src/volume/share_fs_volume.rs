// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use tokio::sync::RwLock;

use super::Volume;
use crate::share_fs::{MountedInfo, ShareFs, ShareFsVolumeConfig};
use kata_types::mount;

const SYS_MOUNT_PREFIX: [&str; 2] = ["/proc", "/sys"];

// copy file to container's rootfs if filesystem sharing is not supported, otherwise
// bind mount it in the shared directory.
// Ignore /dev, directories and all other device files. We handle
// only regular files in /dev. It does not make sense to pass the host
// device nodes to the guest.
// skip the volumes whose source had already set to guest share dir.
pub(crate) struct ShareFsVolume {
    share_fs: Option<Arc<dyn ShareFs>>,
    mounts: Vec<oci::Mount>,
    storages: Vec<agent::Storage>,
}

pub struct ShareFsFile {
    pub src_file: String,
    pub src: PathBuf,
    pub dest: String,
}

impl ShareFsFile {
    pub async fn new(src_file: String) -> Result<Self> {
        let file_name = Path::new(&src_file).file_name().unwrap().to_str().unwrap();
        let file_name = generate_mount_path("sandbox", file_name);

        let src = match std::fs::canonicalize(&src_file) {
            Err(err) => {
                return Err(anyhow!(format!(
                    "failed to canonicalize file {} {:?}",
                    src_file, err
                )))
            }
            Ok(src) => src,
        };

        info!(sl!(), "src_file : {:?}", src_file);
        //        let file_returned = ShareFsFile::new(file_name.clone());

        info!(sl!(), "src_file : {:?}", file_name);
        Ok(ShareFsFile {
            src_file: file_name,
            src,
            dest: src_file,
        })
    }
    pub async fn get_dest(&self) -> String {
        self.dest.clone()
    }
}

impl ShareFsVolume {
    pub(crate) async fn new(
        share_fs: &Option<Arc<dyn ShareFs>>,
        m: &oci::Mount,
        cid: &str,
        readonly: bool,
    ) -> Result<Self> {
        // The file_name is in the format of "sandbox-{uuid}-{file_name}"
        let file_name = Path::new(&m.source).file_name().unwrap().to_str().unwrap();
        let file_name = generate_mount_path("sandbox", file_name);

        let mut volume = Self {
            share_fs: share_fs.as_ref().map(Arc::clone),
            mounts: vec![],
            storages: vec![],
        };
        match share_fs {
            None => {
                let src = match std::fs::canonicalize(&m.source) {
                    Err(err) => {
                        return Err(anyhow!(format!(
                            "failed to canonicalize file {} {:?}",
                            &m.source, err
                        )))
                    }
                    Ok(src) => src,
                };

                if src.is_file() {
                    // TODO: copy file
                    debug!(sl!(), "FIXME: copy file {}", &m.source);
                    /*let file_size = fs::metadata(src)?.len();

                    let r = agent::CreateCopyFileRequest {
                        Path: file_name,
                        DirMode: None,
                        FileMode: src?.st_mode(),
                        FileSize: src?.len(),
                        Uid: src?.st_uid(),
                        Gid: src?.st_gid(),
                        ..Default::default()
                    };

                    self.agent
                        .copy_file(r)
                        .await
                        .context("agent create container")?;*/
                    /*let file_returned = ShareFsFile::new(file_name, src);*/
                } else {
                    debug!(
                        sl!(),
                        "Ignoring non-regular file as FS sharing not supported. mount: {:?}", m
                    );
                }
            }
            Some(share_fs) => {
                let share_fs_mount = share_fs.get_share_fs_mount();
                let mounted_info_set = share_fs.mounted_info_set();
                let mut mounted_info_set = mounted_info_set.lock().await;
                if let Some(mut mounted_info) = mounted_info_set.get(&m.source).cloned() {
                    // Mounted at least once
                    let guest_path = mounted_info
                        .guest_path
                        .clone()
                        .as_os_str()
                        .to_str()
                        .unwrap()
                        .to_owned();
                    if !readonly && mounted_info.readonly() {
                        // The current mount should be upgraded to readwrite permission
                        info!(
                            sl!(),
                            "The mount will be upgraded, mount = {:?}, cid = {}", m, cid
                        );
                        share_fs_mount
                            .upgrade_to_rw(
                                &mounted_info
                                    .file_name()
                                    .context("get name of mounted info")?,
                            )
                            .await
                            .context("upgrade mount")?;
                    }
                    if readonly {
                        mounted_info.ro_ref_count += 1;
                    } else {
                        mounted_info.rw_ref_count += 1;
                    }
                    mounted_info_set.insert(m.source.clone(), mounted_info);

                    volume.mounts.push(oci::Mount {
                        destination: m.destination.clone(),
                        r#type: "bind".to_string(),
                        source: guest_path,
                        options: m.options.clone(),
                    })
                } else {
                    // Not mounted ever
                    let mount_result = share_fs_mount
                        .share_volume(&ShareFsVolumeConfig {
                            // The scope of shared volume is sandbox
                            cid: String::from(""),
                            source: m.source.clone(),
                            target: file_name.clone(),
                            readonly,
                            mount_options: m.options.clone(),
                            mount: m.clone(),
                            is_rafs: false,
                        })
                        .await
                        .context("mount shared volume")?;
                    let mounted_info = MountedInfo::new(
                        PathBuf::from_str(&mount_result.guest_path)
                            .context("convert guest path")?,
                        readonly,
                    );
                    mounted_info_set.insert(m.source.clone(), mounted_info);
                    // set storages for the volume
                    volume.storages = mount_result.storages;

                    // set mount for the volume
                    volume.mounts.push(oci::Mount {
                        destination: m.destination.clone(),
                        r#type: "bind".to_string(),
                        source: mount_result.guest_path,
                        options: m.options.clone(),
                    });
                }
            }
        }
        Ok(volume)
    }
}

#[async_trait]
impl Volume for ShareFsFile {
    fn get_volume_mount(&self) -> anyhow::Result<Vec<oci::Mount>> {
        Ok(vec![])
    }

    fn get_storage(&self) -> Result<Vec<agent::Storage>> {
        Ok(vec![])
    }

    async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
        Ok(())
    }
    fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

#[async_trait]
impl Volume for ShareFsVolume {
    fn get_volume_mount(&self) -> anyhow::Result<Vec<oci::Mount>> {
        Ok(self.mounts.clone())
    }

    fn get_storage(&self) -> Result<Vec<agent::Storage>> {
        Ok(self.storages.clone())
    }

    async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
        let share_fs = match self.share_fs.as_ref() {
            Some(fs) => fs,
            None => return Ok(()),
        };

        let mounted_info_set = share_fs.mounted_info_set();
        let mut mounted_info_set = mounted_info_set.lock().await;
        for m in self.mounts.iter() {
            let (host_source, mut mounted_info) = match mounted_info_set
                .iter()
                .find(|entry| entry.1.guest_path.as_os_str().to_str().unwrap() == m.source)
                .map(|entry| (entry.0.to_owned(), entry.1.clone()))
            {
                Some(entry) => entry,
                None => {
                    warn!(
                        sl!(),
                        "The mounted info for guest path {} not found", m.source
                    );
                    continue;
                }
            };

            let old_readonly = mounted_info.readonly();

            if m.options.iter().any(|opt| *opt == "ro") {
                mounted_info.ro_ref_count -= 1;
            } else {
                mounted_info.rw_ref_count -= 1;
            }

            debug!(
                sl!(),
                "Ref count for {} was updated to {} due to volume cleanup",
                host_source,
                mounted_info.ref_count()
            );
            let share_fs_mount = share_fs.get_share_fs_mount();
            let file_name = mounted_info.file_name()?;

            if mounted_info.ref_count() > 0 {
                // Downgrade to readonly if no container needs readwrite permission
                if !old_readonly && mounted_info.readonly() {
                    info!(sl!(), "Downgrade {} to readonly due to no container that needs readwrite permission", host_source);
                    share_fs_mount
                        .downgrade_to_ro(&file_name)
                        .await
                        .context("Downgrade volume")?;
                }
                mounted_info_set.insert(host_source.clone(), mounted_info);
            } else {
                info!(
                    sl!(),
                    "The path will be umounted due to no references, host_source = {}", host_source
                );
                mounted_info_set.remove(&host_source);
                // Umount the volume
                share_fs_mount
                    .umount_volume(&file_name)
                    .await
                    .context("Umount volume")?
            }
        }

        Ok(())
    }

    fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

pub fn is_share_fs_file(m: &oci::Mount) -> bool {
    is_file(&m.destination)
}

pub(crate) fn is_share_fs_volume(m: &oci::Mount) -> bool {
    (m.r#type == "bind" || m.r#type == mount::KATA_EPHEMERAL_VOLUME_TYPE)
        && !is_host_device(&m.destination)
        && !is_system_mount(&m.source)
        && !is_file(&m.source)
}

fn is_file(dest: &str) -> bool {
    matches!(dest, "/etc/resolv.conf" | "/etc/hostname" | "/etc/hosts")
}

fn is_host_device(dest: &str) -> bool {
    if dest == "/dev" {
        return true;
    }

    if dest.starts_with("/dev/") {
        let src = match std::fs::canonicalize(dest) {
            Err(_) => return false,
            Ok(src) => src,
        };

        if src.is_file() {
            return false;
        }

        return true;
    }

    false
}

// Skip mounting certain system paths("/sys/*", "/proc/*")
// from source on the host side into the container as it does not
// make sense to do so.
// Agent will support this kind of bind mount.
fn is_system_mount(src: &str) -> bool {
    for p in SYS_MOUNT_PREFIX {
        let sub_dir_p = format!("{}/", p);
        if src == p || src.contains(sub_dir_p.as_str()) {
            return true;
        }
    }
    false
}

// Note, don't generate random name, attaching rafs depends on the predictable name.
pub fn generate_mount_path(id: &str, file_name: &str) -> String {
    let mut nid = String::from(id);
    if nid.len() > 10 {
        nid = nid.chars().take(10).collect();
    }

    let mut uid = uuid::Uuid::new_v4().to_string();
    let uid_vec: Vec<&str> = uid.splitn(2, '-').collect();
    uid = String::from(uid_vec[0]);

    format!("{}-{}-{}", nid, uid, file_name)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_system_mount() {
        let sys_dir = "/sys";
        let proc_dir = "/proc";
        let sys_sub_dir = "/sys/fs/cgroup";
        let proc_sub_dir = "/proc/cgroups";
        let not_sys_dir = "/root";

        assert!(is_system_mount(sys_dir));
        assert!(is_system_mount(proc_dir));
        assert!(is_system_mount(sys_sub_dir));
        assert!(is_system_mount(proc_sub_dir));
        assert!(!is_system_mount(not_sys_dir));
    }
}
