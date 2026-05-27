use serde::de::DeserializeOwned;

pub(crate) fn parse<T>(text: &str) -> std::result::Result<T, String>
where
    T: DeserializeOwned,
{
    let parse_options = jsonc_parser::ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        ..Default::default()
    };
    jsonc_parser::parse_to_serde_value(text, &parse_options).map_err(|e| e.to_string())
}
