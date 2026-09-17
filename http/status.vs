package http

public struct Status {
    public static let OK: int32 = 200
    public static let Created: int32 = 201
    public static let Accepted: int32 = 202
    public static let NoContent: int32 = 204
    public static let MovedPermanently: int32 = 301
    public static let Found: int32 = 302
    public static let SeeOther: int32 = 303
    public static let NotModified: int32 = 304
    public static let BadRequest: int32 = 400
    public static let Unauthorized: int32 = 401
    public static let Forbidden: int32 = 403
    public static let NotFound: int32 = 404
    public static let MethodNotAllowed: int32 = 405
    public static let InternalServerError: int32 = 500
    public static let BadGateway: int32 = 502
    public static let ServiceUnavailable: int32 = 503
}

public func StatusText(_ code: int32) -> string {
    switch code {
    case 200: return "OK"
    case 201: return "Created"
    case 202: return "Accepted"
    case 204: return "No Content"
    case 301: return "Moved Permanently"
    case 302: return "Found"
    case 303: return "See Other"
    case 304: return "Not Modified"
    case 400: return "Bad Request"
    case 401: return "Unauthorized"
    case 403: return "Forbidden"
    case 404: return "Not Found"
    case 405: return "Method Not Allowed"
    case 500: return "Internal Server Error"
    case 502: return "Bad Gateway"
    case 503: return "Service Unavailable"
    default:  return "Unknown"
    }
}
