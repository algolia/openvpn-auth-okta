package utils

import (
  "regexp"
  "os"
)
 

func GetEnv(key, fallback string) string {
  if value, ok := os.LookupEnv(key); ok {
    if value == "" {
      return fallback
    }
    return value
  }
  return fallback
}

func CheckUsernameFormat(name string) bool {
  /* OpenVPN doc says:
  To protect against a client passing a maliciously formed username or password string,
  the username string must consist only of these characters:
  alphanumeric, underbar ('_'), dash ('-'), dot ('.'), or at ('@').
  */
  match, err := regexp.MatchString(`^([[:alnum:]]|[_\-\.@])*$`, name);
  if err != nil || !match {
    return false
  }
  return true
}

// Check that path is not group or other writable
func CheckNotWritable(path string) bool {
  sIWGRP := 0b000010000 // Group write permissions
  sIWOTH := 0b000000010 // Other write permissions

  fileInfo, err := os.Stat(path)
  if err != nil {
    return false
  }

  fileMode := fileInfo.Mode().Perm()
  if int(fileMode)&sIWGRP == sIWGRP || int(fileMode)&sIWOTH == sIWOTH {
    return false
  }
  return true
}

func RemoveEmptyStrings(s []string) []string {
  var r []string
  for _, str := range s {
    if str != "" {
      r = append(r, str)
    }
  }
  return r
}
