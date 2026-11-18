import Lake
open Lake DSL

/-
  A package that uses TlsServer links OpenSSL where it builds an executable:

  require TlsServer from git "https://github.com/Open-MBEE/tls-server.lean" @ "<commit>"

  lean_exe myserver where
    moreLinkArgs := #["-lssl", "-lcrypto"]
-/

package TlsServer

@[default_target] lean_lib TlsServer where
  globs := #[.andSubmodules `TlsServer]

/-- `lake test`: one connection served over https on the loopback and fetched by the `curl` program. -/
@[test_driver]
lean_exe test where
  srcDir := "test"
  root := `Test
  moreLinkArgs := #["-lssl", "-lcrypto"]

/-- The shim over OpenSSL; its headers come from the system (`libssl-dev`). -/
target leantls.o pkg : System.FilePath := do
  let oFile := pkg.buildDir / "native" / "leantls.o"
  let srcJob ← inputTextFile <| pkg.dir / "native" / "leantls.cpp"
  buildO oFile srcJob #["-I", (← getLeanIncludeDir).toString] #["-fPIC"]

extern_lib libleantls pkg := do
  let name := nameToStaticLib "leantls"
  buildStaticLib (pkg.sharedLibDir / name) #[← leantls.o.fetch]
