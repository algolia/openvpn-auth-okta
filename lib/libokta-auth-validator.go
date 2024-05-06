// SPDX-FileCopyrightText: 2023-Present Algolia
//
// SPDX-License-Identifier: MPL-2.0
//
// Copyright 2023-Present Algolia
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.


/*
This lib is meant to be used along with OpenVPN:
it's purpose is to be dynamically loaded (using dlopen/dlsyms/...)
by a C "plugin wrapper".
The following C functions are exported (and interesting):
 - ArgsOktaAuthValidatorV2 * oav_args_from_env_v2(const char *envp[])
   that creates an plugin argument dedicated struct from the OPENVPN_PLUGIN env
 - extern void OktaAuthValidatorV2(ArgsOktaAuthValidatorV2* args)
   that run the Go OktaAuthValidator authentication (using the previously created struct)

*/
package main

import (
	"gopkg.in/algolia/openvpn-auth-okta.v2/pkg/validator"
)

/*
#ifndef _OKTA_AUTH_VALIDATOR_
#define _OKTA_AUTH_VALIDATOR_
#include <stdlib.h>
#include <string.h>

// Given an environmental variable name, search
// the envp array for its value, returning it
// if found or NULL otherwise.
// From https://github.com/OpenVPN/openvpn/blob/master/sample/sample-plugins/log/log_v3.c
static const char *
get_env(const char *name, const char *envp[])
{
  if (envp)
  {
    int i;
    const int namelen = strlen(name);
    for (i = 0; envp[i]; ++i)
    {
      if (!strncmp(envp[i], name, namelen))
      {
        const char *cp = envp[i] + namelen;
        if (*cp == '=')
        {
          return cp + 1;
        }
      }
    }
  }
  // Return an empty string here (as expected by the Golang c-shared lib)
  return "";
}

// Used to pass arguments to OktaAuthValidatorV2()
// None of this should be null, an empty string is at least expected
typedef struct {
	const char *CtrFile;
	const char *IP;
	const char *CN;
	const char *User;
	const char *Pass;
} ArgsOktaAuthValidatorV2;

// Extract from envp all what's needed to populate a struct suitable
// for OktaAuthValidatorV2
// The returned object has to be freed
static ArgsOktaAuthValidatorV2 *
oav_args_from_env_v2(const char *envp[])
{
  ArgsOktaAuthValidatorV2* go_args = (ArgsOktaAuthValidatorV2 *) calloc(1, sizeof(ArgsOktaAuthValidatorV2));
  if(go_args)
  {
    go_args->CtrFile = get_env("auth_control_file", envp);
    go_args->IP = get_env("untrusted_ip", envp);
    go_args->CN = get_env("common_name", envp);
    go_args->User = get_env("username", envp);
    go_args->Pass = get_env("password", envp);
  }
  return go_args;
}
#endif
*/
import "C"

type PluginEnv = validator.PluginEnv

//export OktaAuthValidatorV2
func OktaAuthValidatorV2(args *C.ArgsOktaAuthValidatorV2) {
	pluginEnv := &PluginEnv{
		Username:    C.GoString(args.User),
		CommonName:  C.GoString(args.CN),
		Password:    C.GoString(args.Pass),
		ClientIp:    C.GoString(args.IP),
		ControlFile: C.GoString(args.CtrFile),
	}

	v := validator.New()
	if res := v.Setup(true, nil, pluginEnv); !res {
		return
	}
	_ = v.Authenticate()
	v.WriteControlFile()
}

//export OktaAuthValidator
// Deprecated: replaced by OktaAuthValidatorV2
func OktaAuthValidator(ctrF *C.char, ip *C.char, cn *C.char, user *C.char, pass *C.char) {
	pluginEnv := &PluginEnv{
		Username:    C.GoString(user),
		CommonName:  C.GoString(cn),
		Password:    C.GoString(pass),
		ClientIp:    C.GoString(ip),
		ControlFile: C.GoString(ctrF),
	}

	v := validator.New()
	if res := v.Setup(true, nil, pluginEnv); !res {
		return
	}
	_ = v.Authenticate()
	v.WriteControlFile()
}

func main() {
}
