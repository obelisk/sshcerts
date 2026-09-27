use sshcerts::ssh::AllowedSigner;

// This test has its own binary so setting TZ does not affect other tests.
#[test]
fn parse_allowed_signer_dst_local_times() {
    std::env::set_var("TZ", "America/New_York");
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";

    // 01:30 happens twice on 2024-11-03. Expect the earlier one, in EDT.
    let allowed_signer = AllowedSigner::from_string(&format!("mitchell@confurious.io valid-after=202411030130 {key}"));
    assert_eq!(allowed_signer.unwrap().valid_after, Some(1730611800));

    // 02:30 does not exist on 2024-03-10. Like mktime, expect the EST offset from before the gap.
    let allowed_signer = AllowedSigner::from_string(&format!("mitchell@confurious.io valid-after=202403100230 {key}"));
    assert_eq!(allowed_signer.unwrap().valid_after, Some(1710055800));
}
