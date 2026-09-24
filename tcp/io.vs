package tcp

import "io"

// A TcpStream is an async stream as io means one: io.Copy,
// io.AsyncBufferedReader, io.ReadToEnd and the rest take it. Close is not
// io.Closer's, because closing a stream consumes it.
extension TcpStream: io.AsyncReader, io.AsyncWriter {}
