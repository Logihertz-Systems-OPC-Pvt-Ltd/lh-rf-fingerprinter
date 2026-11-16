Name:           lh-rf-fingerprinter
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-rf-fingerprint - Multivariate Mahalanobis Physical Transmitter Distance
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-rf-fingerprinter
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
Physical-layer RF transmitter fingerprinting engine extracting Carrier Frequency Offset (CFO), IQ amplitude/phase skew, LO phase noise, and PA transient features for Mahalanobis-distance rogue SDR detection.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-rf-fingerprint ]; then
    install -m 0755 bin/lh-rf-fingerprint %{buildroot}%{_bindir}/lh-rf-fingerprint
elif [ -f lh-rf-fingerprint ]; then
    install -m 0755 lh-rf-fingerprint %{buildroot}%{_bindir}/lh-rf-fingerprint
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
