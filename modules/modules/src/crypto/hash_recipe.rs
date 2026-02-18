use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::{ModuleOption, ModuleOptionKind, ModuleOptionValue, ModuleOptions};

#[derive(Debug, Clone)]
enum RecipeValue {
    Text(String),
    Bytes(Vec<u8>),
}

impl RecipeValue {
    fn into_bytes(self) -> Vec<u8> {
        match self {
            RecipeValue::Text(text) => text.into_bytes(),
            RecipeValue::Bytes(bytes) => bytes,
        }
    }

    fn into_text(self, function_name: &str) -> Result<String, String> {
        match self {
            RecipeValue::Text(text) => Ok(text),
            RecipeValue::Bytes(bytes) => String::from_utf8(bytes).map_err(|_| {
                format!("{function_name} requires UTF-8 text input but received raw bytes")
            }),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct RecipeVariables {
    pass: Option<String>,
    salt: Option<String>,
    salt1: Option<String>,
    salt2: Option<String>,
    username: Option<String>,
    cx: Option<String>,
}

impl RecipeVariables {
    fn from_options(options: &ModuleOptions) -> Self {
        fn read_set_option(options: &ModuleOptions, key: &str) -> Option<String> {
            options.get(key).and_then(|opt| {
                if opt.value.is_some() {
                    Some(opt.value_as_string())
                } else {
                    None
                }
            })
        }

        RecipeVariables {
            pass: read_set_option(options, "PASS"),
            salt: read_set_option(options, "SALT"),
            salt1: read_set_option(options, "SALT1"),
            salt2: read_set_option(options, "SALT2"),
            username: read_set_option(options, "USERNAME"),
            cx: read_set_option(options, "CX"),
        }
    }

    fn resolve(&self, name: &str) -> Result<RecipeValue, String> {
        let key = name.to_ascii_lowercase();
        match key.as_str() {
            "pass" => self.resolve_required("PASS", &self.pass),
            "salt" => self.resolve_required("SALT", &self.salt),
            "salt1" => self.resolve_required("SALT1", &self.salt1),
            "salt2" => self.resolve_required("SALT2", &self.salt2),
            "username" => self.resolve_required("USERNAME", &self.username),
            "cx" => self.resolve_required("CX", &self.cx),
            _ => Err(format!("unknown symbol: {name}")),
        }
    }

    fn resolve_required(
        &self,
        option_name: &str,
        value: &Option<String>,
    ) -> Result<RecipeValue, String> {
        match value {
            Some(text) => Ok(RecipeValue::Text(text.clone())),
            None => Err(format!(
                "missing required option {option_name} for recipe variable"
            )),
        }
    }
}

struct RecipeParser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
    variables: &'a RecipeVariables,
}

impl<'a> RecipeParser<'a> {
    fn new(input: &'a str, variables: &'a RecipeVariables) -> Self {
        RecipeParser {
            input,
            bytes: input.as_bytes(),
            pos: 0,
            variables,
        }
    }

    fn parse(mut self) -> Result<RecipeValue, String> {
        let value = self.parse_expression()?;
        self.skip_whitespace();
        if self.pos != self.bytes.len() {
            return Err(format!(
                "unexpected token near position {} in recipe",
                self.pos
            ));
        }
        Ok(value)
    }

    fn parse_expression(&mut self) -> Result<RecipeValue, String> {
        let mut value = self.parse_primary()?;
        loop {
            self.skip_whitespace();
            if !self.consume_if(b'.') {
                break;
            }
            let rhs = self.parse_primary()?;
            let mut merged = value.into_bytes();
            merged.extend(rhs.into_bytes());
            value = RecipeValue::Bytes(merged);
        }
        Ok(value)
    }

    fn parse_primary(&mut self) -> Result<RecipeValue, String> {
        self.skip_whitespace();
        let Some(current) = self.peek() else {
            return Err("unexpected end of recipe".to_string());
        };

        match current {
            b'$' => {
                self.pos += 1;
                let name = self.parse_identifier()?;
                self.variables.resolve(&name)
            }
            b'\'' => self.parse_string_literal(),
            b'(' => {
                self.pos += 1;
                let value = self.parse_expression()?;
                self.skip_whitespace();
                self.expect_byte(b')', "expected ')'")?;
                Ok(value)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let name = self.parse_identifier()?;
                self.skip_whitespace();
                if self.consume_if(b'(') {
                    self.parse_function_call(&name)
                } else {
                    self.variables.resolve(&name)
                }
            }
            _ => Err(format!(
                "invalid token '{}' near position {}",
                current as char, self.pos
            )),
        }
    }

    fn parse_function_call(&mut self, name: &str) -> Result<RecipeValue, String> {
        let mut args = Vec::new();
        self.skip_whitespace();
        if !self.consume_if(b')') {
            loop {
                args.push(self.parse_expression()?);
                self.skip_whitespace();
                if self.consume_if(b',') {
                    self.skip_whitespace();
                    continue;
                }
                self.expect_byte(b')', "expected ')' to close function call")?;
                break;
            }
        }

        evaluate_function(name, args)
    }

    fn parse_string_literal(&mut self) -> Result<RecipeValue, String> {
        self.expect_byte(b'\'', "expected string literal")?;
        let mut out = Vec::new();

        while let Some(byte) = self.peek() {
            self.pos += 1;
            if byte == b'\'' {
                let text = String::from_utf8(out)
                    .map_err(|_| "string literal must be UTF-8".to_string())?;
                return Ok(RecipeValue::Text(text));
            }
            if byte == b'\\' {
                let escaped = self
                    .peek()
                    .ok_or_else(|| "unterminated escape sequence".to_string())?;
                self.pos += 1;
                out.push(escaped);
                continue;
            }
            out.push(byte);
        }

        Err("unterminated string literal".to_string())
    }

    fn parse_identifier(&mut self) -> Result<String, String> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' {
                self.pos += 1;
                continue;
            }
            break;
        }
        if self.pos == start {
            return Err(format!("expected identifier near position {}", self.pos));
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect_byte(&mut self, expected: u8, message: &str) -> Result<(), String> {
        let Some(current) = self.peek() else {
            return Err(message.to_string());
        };
        if current != expected {
            return Err(message.to_string());
        }
        self.pos += 1;
        Ok(())
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            return true;
        }
        false
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
}

fn expect_arity(name: &str, args: &[RecipeValue], expected: usize) -> Result<(), String> {
    if args.len() != expected {
        return Err(format!(
            "{name} expects {expected} argument(s), got {}",
            args.len()
        ));
    }
    Ok(())
}

fn evaluate_function(name: &str, args: Vec<RecipeValue>) -> Result<RecipeValue, String> {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "md5" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(md5::digest_hex(&arg.into_bytes())))
        }
        "sha1" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(sha1::digest_hex(&arg.into_bytes())))
        }
        "sha224" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(sha224::digest_hex(&arg.into_bytes())))
        }
        "sha256" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(sha256::digest_hex(&arg.into_bytes())))
        }
        "sha384" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(sha384::digest_hex(&arg.into_bytes())))
        }
        "sha512" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(sha512::digest_hex(&arg.into_bytes())))
        }
        "sha256_bin" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Bytes(
                sha256::digest(&arg.into_bytes()).to_vec(),
            ))
        }
        "sha512_bin" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Bytes(
                sha512::digest(&arg.into_bytes()).to_vec(),
            ))
        }
        "blake2b_256" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(blake2b_256::digest_hex(
                &arg.into_bytes(),
            )))
        }
        "blake2b_512" => {
            expect_arity(name, &args, 1)?;
            let arg = args.into_iter().next().expect("arity checked");
            Ok(RecipeValue::Text(blake2b_512::digest_hex(
                &arg.into_bytes(),
            )))
        }
        "utf16le" => {
            expect_arity(name, &args, 1)?;
            let text = args
                .into_iter()
                .next()
                .expect("arity checked")
                .into_text(name)?;
            let mut encoded = Vec::with_capacity(text.len() * 2);
            for code in text.encode_utf16() {
                let le = code.to_le_bytes();
                encoded.push(le[0]);
                encoded.push(le[1]);
            }
            Ok(RecipeValue::Bytes(encoded))
        }
        "strtoupper" => {
            expect_arity(name, &args, 1)?;
            let text = args
                .into_iter()
                .next()
                .expect("arity checked")
                .into_text(name)?;
            Ok(RecipeValue::Text(text.to_ascii_uppercase()))
        }
        _ => Err(format!("unsupported function in recipe: {name}")),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn build_recipe_options() -> ModuleOptions {
    ModuleOptions::new(vec![
        ModuleOption::new(
            "RECIPE",
            "Hash recipe expression, e.g. md5($pass.$salt)",
            ModuleOptionKind::String,
            true,
        ),
        ModuleOption::new("PASS", "Password input", ModuleOptionKind::String, false),
        ModuleOption::new("SALT", "Salt input", ModuleOptionKind::String, false),
        ModuleOption::new("SALT1", "Salt input 1", ModuleOptionKind::String, false),
        ModuleOption::new("SALT2", "Salt input 2", ModuleOptionKind::String, false),
        ModuleOption::new(
            "USERNAME",
            "Username input",
            ModuleOptionKind::String,
            false,
        ),
        ModuleOption::new(
            "CX",
            "Custom token variable",
            ModuleOptionKind::String,
            false,
        ),
        ModuleOption::new(
            "HASH",
            "Optional expected output for verify mode",
            ModuleOptionKind::String,
            false,
        ),
        ModuleOption::new(
            "OUTPUT_HEX",
            "Hex-encode raw byte outputs",
            ModuleOptionKind::Bool,
            false,
        )
        .with_default(ModuleOptionValue::Bool(true)),
    ])
}

pub struct HashRecipeModule {
    base: ModuleBase,
}

impl HashRecipeModule {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_recipe",
            "Compute or verify composable hash recipes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("recipe")
        .with_platform("cross")
        .with_entrypoint("module.rs");

        HashRecipeModule {
            base: ModuleBase::new(metadata, build_recipe_options()),
        }
    }
}

impl Module for HashRecipeModule {
    fn metadata(&self) -> &ModuleMetadata {
        self.base.metadata()
    }

    fn options(&self) -> &ModuleOptions {
        self.base.options()
    }

    fn options_mut(&mut self) -> &mut ModuleOptions {
        self.base.options_mut()
    }

    fn run(&mut self, _ctx: &ModuleContext) -> Result<ModuleResult, ModuleError> {
        self.base.validate()?;

        let recipe = self
            .options()
            .get("RECIPE")
            .map(|opt| opt.value_as_string())
            .unwrap_or_default();
        let expected = self
            .options()
            .get("HASH")
            .map(|opt| opt.value_as_string())
            .unwrap_or_default();
        let output_hex = self
            .options()
            .get("OUTPUT_HEX")
            .map(|opt| opt.value_as_string())
            .unwrap_or_else(|| "true".to_string())
            .eq_ignore_ascii_case("true");

        let variables = RecipeVariables::from_options(self.options());
        let value = RecipeParser::new(&recipe, &variables)
            .parse()
            .map_err(|error| ModuleError::Execution(format!("invalid recipe: {error}")))?;

        let computed = match value {
            RecipeValue::Text(text) => text,
            RecipeValue::Bytes(bytes) => {
                if output_hex {
                    encode_hex(&bytes)
                } else {
                    String::from_utf8(bytes).map_err(|_| {
                        ModuleError::Execution(
                            "raw output is not valid UTF-8; enable OUTPUT_HEX".to_string(),
                        )
                    })?
                }
            }
        };

        if expected.trim().is_empty() {
            return Ok(ModuleResult::ok(&format!("recipe output: {computed}")));
        }

        let is_match = computed.trim().eq_ignore_ascii_case(expected.trim());
        Ok(ModuleResult::ok(&format!(
            "recipe match: {}",
            if is_match { "true" } else { "false" }
        )))
    }
}

pub struct HashRecipeFactory;

impl ModuleFactory for HashRecipeFactory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_recipe",
                "Compute or verify composable hash recipes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("recipe")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashRecipeModule::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_module() -> HashRecipeModule {
        let mut module = HashRecipeModule::new();
        module
            .options_mut()
            .set("PASS", "P@ssw0rd!")
            .expect("set pass");
        module.options_mut().set("SALT", "NaCl").expect("set salt");
        module
            .options_mut()
            .set("SALT1", "pepper")
            .expect("set salt1");
        module
            .options_mut()
            .set("SALT2", "spice")
            .expect("set salt2");
        module
            .options_mut()
            .set("USERNAME", "alice")
            .expect("set username");
        module
            .options_mut()
            .set("CX", "CLIENTCHALLENGE")
            .expect("set cx");
        module
    }

    #[test]
    fn hash_recipe_vectors() {
        let mut module = base_module();
        let vectors = [
            ("md5(utf16le($pass))", "02c7f6d98465638c4ac5a1c7a744d92b"),
            (
                "sha1(utf16le($pass))",
                "ba380c17a7b2e0233a89896e6b4d412ced541c40",
            ),
            (
                "sha256(utf16le($pass))",
                "a0e9924a866cce0eecbcb37fd8081ed5ce8e319477735dbd22edbdadcaefca8e",
            ),
            (
                "sha384(utf16le($pass))",
                "a0a046825cc819c7a26c5a9178092b90de6e8fc9f0e762192614cb7348e9c91d41a605a4c9e6aa3d0871ea41f9538bfe",
            ),
            (
                "sha512(utf16le($pass))",
                "53cff3d1c455f11e69f9927538a328fd298e6d6b4be66966b336a1343f9ebad09d8e46247ae8872a0dd684ab451e7fe279c9c9976e80d0eed9cfcc61bf346826",
            ),
            (
                "BLAKE2b-256($pass.$salt)",
                "ecf578e09387fabcc572567b6ba611d5f39b5e7905d9ef469a7e4959d54fc9bd",
            ),
            (
                "BLAKE2b-256($salt.$pass)",
                "058109f1d7ea6ea0b1d387c1f90272068a9cff29a8b0f34e8b6f2eaeb04ce1fc",
            ),
            (
                "BLAKE2b-512($pass.$salt)",
                "e41e873b650ed494290584f302acd9e6c9a1d675e9b595bd282551d059993ea823136d77ef9febd47a31a793697a463e4f2b37f84026579c9874e864bf34471e",
            ),
            (
                "BLAKE2b-512($salt.$pass)",
                "4292f3a00e926fa8f7521fa81c48fae25c7ecd0da2bb8f7b29827ce2ac6418db0db0caf39c07ed0c1a1dd208704147cc3d07bee379efcc14a8f81800f611b5be",
            ),
            ("md5($pass.$salt)", "ba06b06e943d2633689d468b9cd8d36f"),
            ("md5($salt.$pass)", "f0ab99cbdeb45905f7277efabb18c629"),
            ("md5($salt.$pass.$salt)", "5ce4a451ce4965738878a21a95f2660f"),
            ("md5($salt.md5($pass))", "c8f6480c87ae1ab6f2c3469aefe4b58f"),
            (
                "md5($salt.md5($pass).$salt)",
                "4c8ff6cef0cdfae7e556dae5df13aeab",
            ),
            (
                "md5($salt.md5($pass.$salt))",
                "9dc3a8b10bdc4d2832c5713aafe9c5d2",
            ),
            (
                "md5($salt.md5($salt.$pass))",
                "4d5e148a7d54649dea55651dc17ae639",
            ),
            (
                "md5($salt.sha1($salt.$pass))",
                "9822c169790e4d4ac137843a49b5b9a7",
            ),
            (
                "md5($salt.utf16le($pass))",
                "3eddcb6a3d5f3a6d736502ad0195b491",
            ),
            (
                "md5($salt1.$pass.$salt2)",
                "bb52e357e9b2b5c0ca0ac9a9f3338a60",
            ),
            (
                "md5($salt1.sha1($salt2.$pass))",
                "54ef30e419db569f40131b44499c8173",
            ),
            (
                "md5($salt1.strtoupper(md5($salt2.$pass)))",
                "7b8444bc320850d1263eba865aeab3e2",
            ),
            ("md5(md5($pass))", "8a297d8f5cc6b79450f0eb982fdbc69e"),
            (
                "md5(md5($pass).md5($salt))",
                "5991b1352633369f7ae1038191e1d5de",
            ),
            ("md5(md5($pass.$salt))", "0640458bb360e1c1c103c3152d4f454f"),
            (
                "md5(md5($salt).md5(md5($pass)))",
                "5858f769269cae6b736343539dbe554f",
            ),
            ("md5(md5(md5($pass)))", "87e9dce8ab198d899c22e07a7f0a0b95"),
            (
                "md5(md5(md5($pass)).$salt)",
                "c50b197708dfd59e2849a7033eedd2a8",
            ),
            (
                "md5(md5(md5($pass).$salt1).$salt2)",
                "3e70ed92fa4486cf2041d00d49d22777",
            ),
            (
                "md5(md5(md5($pass.$salt1)).$salt2)",
                "41cdec81fae6f3711c2cdeb7f6825045",
            ),
            ("md5(sha1($pass))", "2d36b04ea81f480119f542549627fa21"),
            (
                "md5(sha1($pass).$salt)",
                "7461341bdf78383286bb7ad74e35692d",
            ),
            (
                "md5(sha1($pass).md5($pass).sha1($pass))",
                "db9b17302eaca39b5cf4423c8b74cde5",
            ),
            ("md5(sha1($pass.$salt))", "555b86048cc778aa831782ee0a454ac0"),
            (
                "md5(sha1($salt).md5($pass))",
                "3950ae65119bf03a7df48fcc7412fb7b",
            ),
            ("md5(sha1($salt.$pass))", "1527b1894237578c0adbc035dd882e44"),
            (
                "md5(sha1(md5($pass)))",
                "d7cda3c9d96897c4aed5a9a388e5674d",
            ),
            (
                "md5(strtoupper(md5($pass)))",
                "c1f3ddf1d34d2a12dc2362330c252dc9",
            ),
            (
                "md5(utf16le($pass).$salt)",
                "ff60dec270bf005ce76e1093524c7d79",
            ),
            ("sha1($pass.$salt)", "e94c818acdd4badafe1fb6e682256eba3318c158"),
            ("sha1($salt.$pass)", "d6db4c69538c6febe554f9a69264c56de83a771b"),
            (
                "sha1($salt.$pass.$salt)",
                "b5133523eef688997032e2525633aa0eda2ae77c",
            ),
            (
                "sha1($salt.sha1($pass))",
                "37ab05f5161278fe765499ecb93a8096affc8ba4",
            ),
            (
                "sha1($salt.sha1($pass.$salt))",
                "d2c2809f966951e0966494b1e95aa5f39bd36f7d",
            ),
            (
                "sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))",
                "d676d01059c74bccd3d0cb733f24506eaf797503",
            ),
            (
                "sha1($salt.utf16le($pass))",
                "6986d22d64002497c34f2e70ac7fd3ac9a9fedd9",
            ),
            (
                "sha1($salt1.$pass.$salt2)",
                "69e7bb753d701613d8c13ad022457f33391df53d",
            ),
            ("sha1(CX)", "6b1208b0676a21679544b804e947be409fffe5bf"),
            ("sha1(md5($pass))", "52fd60fe03c933418a86a1139d91dbf0d9bb8d26"),
            (
                "sha1(md5($pass).$salt)",
                "52686fe3999800f91fb873f87c256dc879eb11ad",
            ),
            (
                "sha1(md5($pass.$salt))",
                "245a1b3e19fa1d463fe782f24e9e0ee81f1b10bb",
            ),
            (
                "sha1(md5(md5($pass)))",
                "e8526725b8e79bef49a94d046f1c2ac9db1ebcb4",
            ),
            ("sha1(sha1($pass))", "40719cad6997b7c18cbd13b38ca0cfb891621f89"),
            (
                "sha1(sha1($pass).$salt)",
                "f1abd75f8162cd097dad8877c3e65eb695280ad1",
            ),
            (
                "sha1(sha1($salt.$pass.$salt))",
                "4b637e063d2536e83e5767bb16445fd0fa700dff",
            ),
            (
                "sha1(utf16le($pass).$salt)",
                "42d96499fbb9c2ac22e3914fbd58f7ffe8a1af2c",
            ),
            (
                "sha224($pass.$salt)",
                "5aaed8514c83961f10f8afed738837b00e69e781689c096654fc672a",
            ),
            (
                "sha224($salt.$pass)",
                "b249cf898430b88942b6ad3b0b431c3c7d347023ab8e9605c1ab85cb",
            ),
            (
                "sha224(sha1($pass))",
                "e0a0a0fd4fb9f4d83c6f6fc68a8270803a559db1a4306e56d0b25737",
            ),
            (
                "sha224(sha224($pass))",
                "527cf951b23f773c50771344da5a5de0eb8f2047de53b643d4a471df",
            ),
            (
                "sha256($pass.$salt)",
                "d4cdbbdd4479eb96d5f7c28f36371fd7b1ed7f055a9700b76e8a1eb06832a6b2",
            ),
            (
                "sha256($salt.$pass)",
                "1c3b1614def7f35c23eef2bbe070db3d93e750c848a5e601cff05c4607a157cf",
            ),
            (
                "sha256($salt.$pass.$salt)",
                "1018f96d8c674d7f51efa29a62ff54aadddb8fb4a3c440afa3835c67fdf016b2",
            ),
            (
                "sha256($salt.sha256($pass))",
                "03903d2b6d67ace9c543fb0d2f2d0d0b3cd90fedcc40dc9be030c43b11ff45b4",
            ),
            (
                "sha256($salt.sha256_bin($pass))",
                "66d79836ff74b00c936027f7c8a98a2eca83f966e1b6a81e699912fd7c849b91",
            ),
            (
                "sha256($salt.utf16le($pass))",
                "6c25f15ac70bfb6d14c9e9445e26e722cbd3b8dff69900a25a5619e570a0d1ec",
            ),
            (
                "sha256(md5($pass))",
                "05f7ead0a5e087a2f2dcbc859cda3b98922eb1000576aafa5e5c92a287e29e92",
            ),
            (
                "sha256(sha256($pass).$salt)",
                "cb1be588ba4d788ce07a0005e61fb5857131967126cccc2631fe40a65a27a76d",
            ),
            (
                "sha256(sha256($pass.$salt))",
                "201c87ae3d6a14024479518a9e1c08c250fc53235ffd5d9c477894731b6edd9b",
            ),
            (
                "sha256(sha256_bin($pass))",
                "896e65ddb6b64e768bd8e35ac4d264931eb365ca6652d996866b775a7f6f99d5",
            ),
            (
                "sha256(utf16le($pass).$salt)",
                "1791fc08da530cb08fe7950b30e4947d14d3ef10bf4e766f0cd6669445975e67",
            ),
            (
                "sha384($pass.$salt)",
                "7781bbb7eec089afcc5014f2f975433b2b395b097a8fa5c8a9d4747888ee315a130cf048be22d8e1111e5d683f8e6b4f",
            ),
            (
                "sha384($salt.$pass)",
                "9d009adf5903545472723309a9e3e89141325b7b3ca7c9dfb98a61dfafd608d4edcc8d71e9c634c6101836ef8805ed26",
            ),
            (
                "sha384($salt.utf16le($pass))",
                "a84d3ad86e3f0124d290288b7245820d622d23cf79a0a179f72fbdf94dead7e7f3d244fa0670a8f51112b08b98e7037f",
            ),
            (
                "sha384(utf16le($pass).$salt)",
                "05dd29ed898a1ed58e6036d1c48721b6bbc11a8c4408050f6c0535cf254bc1ef19fa919a0487edeb698aa38bb354af38",
            ),
            (
                "sha512($pass.$salt)",
                "f039b6a127f7772117549c777686b431766566fef547fdc0554ca78426272325cf5a70ba051dc1deec4c299ce3688522e1c12edb23b6254c9eee999835c65178",
            ),
            (
                "sha512($salt.$pass)",
                "98f17d7c70110ab6be118eff46c1e16c468b4614b8543720ba648e55c0c837af87a82816b34ce80906392228bef4b85a01edb6f62293dcc25233b36cfe49c862",
            ),
            (
                "sha512($salt.utf16le($pass))",
                "9fa15427d320f465b6a3a6b3b63036d9e1eb7d1f00dac064b60d96169f27dd119a32f3c33ad5314e18de6db0e43f616b692633db810971f0ffce7d7de071f1ed",
            ),
            (
                "sha512(sha512($pass).$salt)",
                "021c019edbeb4846f0124c2a5bdb410ebd6db47c6e2ea0d1f737c002dfb27baa258d0b6324b7d16a31adc3c011bd7fed270783a3237afccc5026e46539c75f1a",
            ),
            (
                "sha512(sha512_bin($pass).$salt)",
                "ca184d2de4d928335f67e5e5a57088cda6eae4bdeb9dce24873261f05bd5e015e83abaabae7412ae4315a8fa0958ff0b32091ee13f91f8323de3cfc7184734c0",
            ),
            (
                "sha512(utf16le($pass).$salt)",
                "c91df543010b4fa5ad4d33b92a0a609ba2c7cf55095d3fcdc897ad1e6e4668c129d363efb5d62aeb1ed2ab735961fb89f87be4093e6ffabc6fc3664e8194d8db",
            ),
        ];

        for (recipe, expected) in vectors {
            module
                .options_mut()
                .set("RECIPE", recipe)
                .expect("set recipe");
            module.options_mut().set("HASH", "").expect("clear hash");
            let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
            assert!(
                result.message.contains(expected),
                "expected {expected} for recipe {recipe}, got {}",
                result.message
            );
        }
    }

    #[test]
    fn hash_recipe_verify_mode() {
        let mut module = base_module();
        module
            .options_mut()
            .set("RECIPE", "sha256(sha256_bin($pass))")
            .expect("set recipe");
        module
            .options_mut()
            .set(
                "HASH",
                "896e65ddb6b64e768bd8e35ac4d264931eb365ca6652d996866b775a7f6f99d5",
            )
            .expect("set hash");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
    }

    #[test]
    fn hash_recipe_rejects_unknown_symbol() {
        let mut module = base_module();
        module
            .options_mut()
            .set("RECIPE", "sha1($unknown)")
            .expect("set recipe");
        let error = module
            .run(&ModuleContext { session_id: 1 })
            .expect_err("must fail");
        assert!(error.to_string().contains("unknown symbol"));
    }
}
