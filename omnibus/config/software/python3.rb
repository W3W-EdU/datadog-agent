name "python3"

default_version "3.12.6"

unless windows?
  dependency "libxcrypt"
  dependency "libffi"
  dependency "ncurses"
  dependency "zlib"
  dependency "bzip2"
  dependency "libsqlite3"
  dependency "liblzma"
  dependency "libyaml"
end
dependency ENV["OMNIBUS_OPENSSL_SOFTWARE"] || "openssl"

source :url => "https://python.org/ftp/python/#{version}/Python-#{version}.tgz",
       :sha256 => "85a4c1be906d20e5c5a69f2466b00da769c221d6a684acfd3a514dbf5bf10a66"

relative_path "Python-#{version}"

python_configure_options = [
  "--without-readline",  # Disables readline support
  "--with-ensurepip=yes" # We upgrade pip later, in the pip3 software definition
]

if mac_os_x?
  python_configure_options.push("--enable-ipv6",
                        "--with-universal-archs=intel",
                        "--enable-shared")
elsif linux_target?
  python_configure_options.push("--enable-shared",
                        "--enable-ipv6")
elsif windows_target?
  python_configure_options.push("--host=x86_64-w64-mingw32")
elsif aix?
  # something here...
end

python_configure_options.push("--with-dbmliborder=")

build do
  # 2.0 is the license version here, not the python version
  license "Python-2.0"

  env = with_standard_compiler_flags(with_embedded_path)
  # Force different defaults for the "optimization settings"
  # This removes the debug symbol generation and doesn't enable all warnings
  env["OPT"] = "-DNDEBUG -fwrapv"
  configure(*python_configure_options, :env => env)
  command "cat --number Makefile"
  command "make -j #{workers}", :env => env
  command "make install", :env => env

  # There exists no configure flag to tell Python to not compile readline support :(
  major, minor, bugfix = version.split(".")

  delete "#{install_dir}/embedded/lib/python#{major}.#{minor}/test"
  block do
    FileUtils.rm_f(Dir.glob("#{install_dir}/embedded/lib/python#{major}.#{minor}/distutils/command/wininst-*.exe"))
  end
end

