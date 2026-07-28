# Intentionally empty. This package's scripts are bundled into the compiled
# plugin (see zeek/scripts/__load__.zeek) and auto-load with it. This stub
# exists only to satisfy zkg's implicit script_dir check and must never
# @load anything — doing so would duplicate the plugin's own script bundle
# under /opt/zeek/share/zeek/site/packages, causing double-declaration
# errors (Type FINGERPRINT::Info has already been declared, etc.) when the
# package is loaded via site policy (e.g. `local`) in addition to the
# plugin's own auto-load.
