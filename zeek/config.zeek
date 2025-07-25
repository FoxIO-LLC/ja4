module FINGERPRINT;

export {
  option delimiter: string = "_";

  # BSD licensed
  option JA4_enabled:    bool = T;
  option JA4_raw:        bool = F;

  # FoxIO license required for JA4+
  option JA4S_enabled:   bool = T;
  option JA4S_raw:   bool = F;

  option JA4H_enabled:   bool = T;
  option JA4H_raw:   bool = F;

  option JA4L_enabled:   bool = T;
  
  option JA4SSH_enabled: bool = T;
  option JA4SSH_max_fingerprints: count = 0; # Maximum number of fingerprints to produce, 0 means no maximum.

  option JA4T_enabled: bool = T;
  option JA4TS_enabled: bool = T;

  option JA4X_enabled:   bool = F;
}
