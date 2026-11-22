SeaORM 2.0.4, from the crates.io release. Three import-only changes gate imports behind the features that use them.
The manifest drops the weak Arrow feature edge from `with-time` because Cargo
otherwise locks the unused Arrow integration and its unmaintained date dependency.
The exporter uses none of the Arrow APIs. Remove this patch when the upstream
release or Cargo resolver can keep those unused packages out of the lockfile.
