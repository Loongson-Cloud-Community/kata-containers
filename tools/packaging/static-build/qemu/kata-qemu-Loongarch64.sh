rm b -rf && mkdir b && cd b && ../configure --disable-live-block-migration --disable-brlapi --disable-docs --disable-curses --disable-gtk --disable-opengl --disable-sdl --enable-spice --disable-vte --disable-vnc --disable-vnc-jpeg --disable-vnc-png --disable-vnc-sasl --disable-auth-pam --disable-glusterfs --disable-libiscsi --disable-libnfs --disable-libssh --disable-bzip2 --disable-lzo --disable-snappy  --disable-slirp --disable-libusb --disable-usb-redir --disable-tcg --disable-debug-tcg --disable-tcg-interpreter --disable-qom-cast-debug --disable-libudev --disable-curl --disable-rdma --disable-tools --enable-virtiofsd --enable-virtfs --disable-bsd-user --disable-linux-user --disable-sparse --disable-vde --disable-xfsctl --disable-libxml2 --disable-nettle --disable-xen --disable-linux-aio --disable-capstone --disable-virglrenderer --disable-replication --disable-smartcard --disable-guest-agent --disable-guest-agent-msi --disable-vvfat --disable-vdi --disable-qed --disable-qcow1 --disable-bochs --disable-cloop --disable-dmg --disable-parallels --enable-kvm --enable-vhost-net --enable-rbd --enable-virtfs --enable-attr --enable-cap-ng --enable-seccomp --enable-malloc-trim --target-list=loongarch64-softmmu --enable-pie --extra-cflags=" -O2 -fno-semantic-interposition -falign-functions=32 -D_FORTIFY_SOURCE=2" --extra-ldflags=" -z noexecstack -z relro -z now" --prefix=/opt/kata --libdir=/opt/kata/lib/kata-qemu --libexecdir=/opt/kata/libexec/kata-qemu --datadir=/opt/kata/share/kata-qemu --with-pkgversion="kata-static${BUILD_SUFFIX}"
