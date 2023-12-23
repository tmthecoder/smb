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

pub type SMBChannel = channel::SMBChannel;
pub type SMBClient = client::SMBClient;
pub type SMBConnection = connection::SMBConnection;
pub type SMBLease = lease::SMBLease;
pub type SMBLeaseTable = lease::SMBLeaseTable;
pub type SMBOpen<T> = open::SMBOpen<T>;
pub type SMBPreauthSession = preauth_session::SMBPreauthSession;
pub type SMBRequest<T> = request::SMBRequest<T>;
pub type SMBSession<T> = session::SMBSession<T>;
pub type SMBServer = server::SMBServer;

pub type SMBServerBuilder = server::SMBServerBuilder;
pub type SMBShare<ConnectAllowed, FilePerms> = share::SMBShare<ConnectAllowed, FilePerms>;
pub type SMBServerDiagnostics = server::SMBServerDiagnostics;
pub type SMBTreeConnect<T> = tree_connect::SMBTreeConnect<T>;
