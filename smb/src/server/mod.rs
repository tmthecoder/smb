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

pub type SMBChannel<T> = channel::SMBChannel<T>;
pub type SMBClient = client::SMBClient;
pub type SMBConnection<T> = connection::SMBConnection<T>;
pub type SMBLease = lease::SMBLease;
pub type SMBLeaseTable = lease::SMBLeaseTable;
pub type SMBOpen<T> = open::SMBOpen<T>;
pub type SMBPreauthSession = preauth_session::SMBPreauthSession;
pub type SMBRequest<T> = request::SMBRequest<T>;
pub type SMBSession<T> = session::SMBSession<T>;
pub type SMBServer = server::SMBServer;
pub type SMBShare<ConnectArgs, FileSecArgs, ConnectAllowed, FilePerms> = share::SMBShare<ConnectArgs, FileSecArgs, ConnectAllowed, FilePerms>;
pub type SMBTreeConnect<T> = tree_connect::SMBTreeConnect<T>;
