pkgname=pam-parallel-fprint
pkgver=1.0.0
pkgrel=1
pkgdesc="A Linux-PAM module that allows for fingerprint (fprintd) and password authorization in parallel"
arch=('x86_64' 'aarch64')
url="https://github.com/mal1k-me/PAM-Parallel-Fprint"
license=('GPL3')
depends=('pam' 'systemd' 'libfprint')
makedepends=('rust' 'cargo')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/mal1k-me/PAM-Parallel-Fprint/archive/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
  cd "${srcdir}/PAM-Parallel-Fprint-${pkgver}"
  cargo build --release
}

package() {
  cd "${srcdir}/PAM-Parallel-Fprint-${pkgver}"
  install -Dm755 target/release/pam_parallel_fprint.so "${pkgdir}/usr/lib/security/pam_parallel_fprint.so"
  install -Dm644 README.md "${pkgdir}/usr/share/doc/${pkgname}/README.md"
  install -Dm644 add_to_pam "${pkgdir}/usr/share/doc/${pkgname}/add_to_pam"
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
