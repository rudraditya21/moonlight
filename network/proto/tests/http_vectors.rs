use proto::http::{HttpMethod, HttpRequest, HttpResponse};

#[test]
fn http_request_golden() {
    let mut req = HttpRequest::new(HttpMethod::Get, "/");
    req.set_header("Host", "example.com");
    let bytes = req.to_bytes().expect("encode");
    let expected = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(bytes, expected);
}

#[test]
fn http_response_golden() {
    let mut resp = HttpResponse::new(200);
    resp.body = b"ok".to_vec();
    let bytes = resp.to_bytes().expect("encode");
    let expected = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    assert_eq!(bytes, expected);
}
