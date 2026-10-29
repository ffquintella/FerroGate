//! Permission names (F20 §7) that front ends check before offering an action.
//! A convenience only: the server's `AdminAuthz` enforces every permission,
//! whatever a client shows or hides.

/// List requests.
pub const REQUEST_LIST: &str = "app_request.list";
/// Approve a request.
pub const APPROVE: &str = "app_request.approve";
/// Deny a request.
pub const DENY: &str = "app_request.deny";
/// List approvals.
pub const APPROVAL_LIST: &str = "approval.list";
/// Edit an approval or freeze a lineage.
pub const UPDATE: &str = "approval.update";
/// Revoke an approval.
pub const REVOKE: &str = "approval.revoke";
/// Add an application directly.
pub const DIRECT_REGISTER: &str = "app.direct_register";
/// List accounts.
pub const ACCOUNT_LIST: &str = "account.list";
