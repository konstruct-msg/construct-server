use tonic::Status;

use construct_server_shared::shared::proto::signaling::v1::{
    signal_route, DeviceTarget, GroupTarget, SignalRoute, UserTarget,
};

pub(crate) fn callee_user_id_from_route(route: Option<&SignalRoute>) -> Result<&str, Status> {
    let route = route.ok_or_else(|| Status::invalid_argument("Offer requires route"))?;
    let target = route
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Offer requires route.target"))?;

    match target {
        signal_route::Target::User(UserTarget { user_id, .. }) => {
            if user_id.is_empty() {
                Err(Status::invalid_argument("route.user.user_id is empty"))
            } else {
                Ok(user_id.as_str())
            }
        }
        signal_route::Target::Device(DeviceTarget { user_id, .. }) => {
            if user_id.is_empty() {
                Err(Status::invalid_argument("route.device.user_id is empty"))
            } else {
                Ok(user_id.as_str())
            }
        }
        signal_route::Target::Group(GroupTarget { .. }) => Err(Status::unimplemented(
            "Group call routing is not implemented yet (use route.user)",
        )),
    }
}
