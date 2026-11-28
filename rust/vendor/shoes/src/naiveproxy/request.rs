use super::{
    naive_padding_stream::{PaddingType, generate_client_padding_header},
    options::Headers,
};
use crate::address::NetLocation;
use http::{HeaderMap, HeaderValue, Method, Request, Version};
use rand::RngExt;
use std::io;

pub(super) fn connect_request(
    target: &NetLocation,
    authorization: &str,
    padding: bool,
    headers: &Headers,
    version: Version,
) -> io::Result<Request<()>> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(super::naive_client_session::format_authority(target))
        .version(version)
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if version == Version::HTTP_2 {
        chromium_h2_headers(&mut request, authorization, padding, headers)?;
        return Ok(request);
    }
    // The fixed wrapper builds identical default fields before choosing H2/H3.
    if !authorization.is_empty() {
        let mut value = HeaderValue::from_str(authorization)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy authorization"))?;
        value.set_sensitive(true);
        request.headers_mut().insert("proxy-authorization", value);
    }
    if padding {
        request.headers_mut().insert("padding",
            HeaderValue::from_str(&generate_client_padding_header()).unwrap());
    }
    let supplied = headers.parsed()?;
    for name in supplied.keys() {
        request.headers_mut().remove(name);
        for value in supplied.get_all(name) {
            request.headers_mut().append(name.clone(), value.clone());
        }
    }
    if !request.headers().contains_key("user-agent") {
        request.headers_mut().insert("user-agent", HeaderValue::from_static(""));
    }
    Ok(request)
}

fn chromium_h2_headers(
    request: &mut Request<()>,
    authorization: &str,
    padding: bool,
    extra: &Headers,
) -> io::Result<()> {
    if !authorization.is_empty() {
        let value = HeaderValue::from_str(authorization).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy authorization")
        })?;
        request.headers_mut().insert("proxy-authorization", value);
    }
    if padding {
        request.headers_mut().insert(
            "padding",
            HeaderValue::from_str(&generate_client_padding_header()).unwrap(),
        );
    }
    // The fixed wrapper merges user headers after defaults. Keep every value.
    let supplied = extra.parsed()?;
    for name in supplied.keys() {
        request.headers_mut().remove(name);
        for value in supplied.get_all(name).iter() {
            let mut value = value.clone();
            // The fixed Cronet wrapper supplies plain string headers; its
            // encoder indexes ordinary fields, including cookie/authorization.
            // This is restricted to the explicit Naive H2 compatibility path.
            value.set_sensitive(false);
            request.headers_mut().append(name.clone(), value);
        }
    }
    let added_user_agent = !request.headers().contains_key("user-agent");
    if added_user_agent {
        request
            .headers_mut()
            .insert("user-agent", HeaderValue::from_static(""));
    }
    let mut order: Vec<_> = request.headers().keys().cloned().collect();
    order.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    order.retain(|name| {
        name != "padding"
            && name != "proxy-authorization"
            && !(added_user_agent && name == "user-agent")
    });
    // Go map iteration admits both default orders; its distribution is not a
    // stable API. Choose either order, without claiming an identical RNG law.
    let defaults = if rand::rng().random_bool(0.5) {
        ["padding", "proxy-authorization"]
    } else {
        ["proxy-authorization", "padding"]
    };
    let mut ordered = Vec::with_capacity(request.headers().keys().count());
    for name in defaults {
        if request.headers().contains_key(name) {
            ordered.push(http::header::HeaderName::from_static(name));
        }
    }
    ordered.extend(order);
    if added_user_agent {
        ordered.push(http::header::USER_AGENT);
    }
    request
        .extensions_mut()
        .insert(h2::client::ChromiumHeaderOrder(ordered));
    Ok(())
}

pub(super) fn response_padding(headers: &HeaderMap, enabled: bool) -> io::Result<PaddingType> {
    if !enabled {
        return Ok(PaddingType::None);
    }
    if let Some(value) = headers.get("padding-type-reply") {
        return value
            .to_str()
            .ok()
            .and_then(|v| v.trim().parse::<u8>().ok())
            .and_then(PaddingType::from_u8)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unsupported Naive padding type")
            });
    }
    Ok(if headers.contains_key("padding") {
        PaddingType::Variant1
    } else {
        PaddingType::None
    })
}

pub(super) fn uot_target(version: u8) -> crate::address::ResolvedLocation {
    NetLocation::new(
        crate::address::Address::Hostname(
            if version == 1 {
                crate::uot::UOT_V1_MAGIC_ADDRESS
            } else {
                crate::uot::UOT_V2_MAGIC_ADDRESS
            }
            .into(),
        ),
        0,
    )
    .into()
}

#[cfg(test)]
mod chromium_request_tests {
    use super::super::options::HeaderValues;
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn h2_and_h3_default_headers_follow_the_fixed_wrapper() {
        let target = NetLocation::from_str("capture.invalid:443", None).unwrap();
        for _ in 0..16 {
            let h2 = connect_request(
                &target,
                "Basic dXNlcjpwYXNz",
                true,
                &Headers::default(),
                Version::HTTP_2,
            )
            .unwrap();
            assert!(!h2.headers()["proxy-authorization"].is_sensitive());
            assert_eq!(h2.headers()["user-agent"], "");
            assert!(!h2.headers().contains_key("padding-type-request"));
            let value = h2.headers()["padding"].as_bytes();
            assert!((30..=61).contains(&value.len()));
            assert!(value[..16].iter().all(|b| b"!#$()+<>?@[]^`{}".contains(b)));
            assert!(value[16..].iter().all(|b| *b == b'~'));
            let order = &h2
                .extensions()
                .get::<h2::client::ChromiumHeaderOrder>()
                .unwrap()
                .0;
            assert_eq!(order.len(), 3);
            assert_eq!(order[2], "user-agent");
            assert!(
                (order[0] == "padding" && order[1] == "proxy-authorization")
                    || (order[1] == "padding" && order[0] == "proxy-authorization")
            );
        }
        let h3 = connect_request(
            &target,
            "Basic dXNlcjpwYXNz",
            true,
            &Headers::default(),
            Version::HTTP_3,
        )
        .unwrap();
        assert!(h3.headers()["proxy-authorization"].is_sensitive());
        assert!(!h3.headers().contains_key("padding-type-request"));
        assert_eq!(h3.headers()["user-agent"], "");
        assert!(
            h3.extensions()
                .get::<h2::client::ChromiumHeaderOrder>()
                .is_none()
        );
        assert!((30..=61).contains(&h3.headers()["padding"].as_bytes().len()));
    }

    #[test]
    fn h2_custom_overrides_and_multiple_values_are_preserved() {
        let headers = Headers(BTreeMap::from([
            ("user-agent".into(), HeaderValues::One("explicit".into())),
            (
                "proxy-authorization".into(),
                HeaderValues::One("Basic explicit".into()),
            ),
            ("padding-type-request".into(), HeaderValues::One("1".into())),
            (
                "x-extra".into(),
                HeaderValues::Many(vec!["first".into(), "second".into()]),
            ),
        ]));
        let target = NetLocation::from_str("capture.invalid:443", None).unwrap();
        let request =
            connect_request(&target, "Basic default", false, &headers, Version::HTTP_2).unwrap();
        assert_eq!(request.headers()["user-agent"], "explicit");
        assert_eq!(request.headers()["proxy-authorization"], "Basic explicit");
        assert!(!request.headers()["proxy-authorization"].is_sensitive());
        assert_eq!(request.headers()["padding-type-request"], "1");
        let values: Vec<_> = request
            .headers()
            .get_all("x-extra")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, ["first", "second"]);
        let order = &request
            .extensions()
            .get::<h2::client::ChromiumHeaderOrder>()
            .unwrap()
            .0;
        assert_eq!(order.iter().filter(|name| *name == "x-extra").count(), 1);
        assert_eq!(order.len(), request.headers().keys().count());
    }
}

#[cfg(test)]
mod chromium_cookie_request_tests {
    use super::super::options::HeaderValues;
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn chromium_config_cookie_is_indexable_only_on_the_naive_h2_path() {
        let extra = Headers(BTreeMap::from([
            ("cookie".into(), HeaderValues::One("a=1; b=2".into())),
            (
                "authorization".into(),
                HeaderValues::One("Bearer explicit".into()),
            ),
        ]));
        let target = NetLocation::from_str("capture.invalid:443", None).unwrap();
        let h2 = connect_request(&target, "Basic dTpw", false, &extra, Version::HTTP_2).unwrap();
        let h3 = connect_request(&target, "Basic dTpw", false, &extra, Version::HTTP_3).unwrap();
        for name in ["cookie", "authorization"] {
            assert!(!h2.headers()[name].is_sensitive());
            assert!(h3.headers()[name].is_sensitive());
            assert_eq!(h2.headers()[name], h3.headers()[name]);
        }
    }
}
