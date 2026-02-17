use modules::{register_builtin_modules, ModuleContext, ModuleRegistryBuilder};

#[test]
fn telnet_module_registered_in_builtins() {
    let mut builder = ModuleRegistryBuilder::new();
    register_builtin_modules(&mut builder);
    let registry = builder.build().expect("build registry");

    let mut module = registry
        .create("exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass")
        .expect("module exists");

    assert_eq!(
        module.metadata().name,
        "exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass"
    );
    module
        .options_mut()
        .set("RHOST", "127.0.0.1")
        .expect("set host");

    // Running without a target server should fail with execution error,
    // but this confirms the full registry -> factory -> module path.
    let result = module.run(&ModuleContext { session_id: 1 });
    assert!(result.is_err());
}
