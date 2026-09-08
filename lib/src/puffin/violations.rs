// use crate::puffin::claims::OpcuaClaim;
// use puffin::claims::SecurityViolationPolicy;
//
// pub struct OpcuaSecurityViolationPolicy;
// impl SecurityViolationPolicy for OpcuaSecurityViolationPolicy {
//     type C = OpcuaClaim;
//
//     fn check_violation(_claims: &[OpcuaClaim]) -> Option<&'static str> {
//         panic!("Not implemented yet for OPC UA");
//     }
// }