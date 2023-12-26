use std::marker::Tuple;

mod client;
mod channel;
mod connection;
mod lease;
mod open;
mod preauth_session;
mod request;
mod server;
mod session;
mod share;
mod tree_connect;

pub type SMBChannel<R, W> = channel::SMBChannel<R, W>;
pub type SMBClient = client::SMBClient;
pub type SMBConnection<R, W> = connection::SMBConnection<R, W>;
pub type SMBLease = lease::SMBLease;
pub type SMBLeaseTable = lease::SMBLeaseTable;
pub type SMBOpen<T, R, W> = open::SMBOpen<T, R, W>;
pub type SMBPreauthSession = preauth_session::SMBPreauthSession;
pub type SMBRequest<T, R, W> = request::SMBRequest<T, R, W>;
pub type SMBSession<T, R, W> = session::SMBSession<T, R, W>;
pub type SMBServer<Addrs, Listener> = server::SMBServer<Addrs, Listener>;
pub type SMBServerBuilder<Addrs, Listener> = server::SMBServerBuilder<Addrs, Listener>;
pub type SMBShare<ConnectAllowed, FilePerms> = share::SMBShare<ConnectAllowed, FilePerms>;
pub type SMBServerDiagnostics = server::SMBServerDiagnostics;
pub type SMBTreeConnect<T, R, W> = tree_connect::SMBTreeConnect<T, R, W>;
