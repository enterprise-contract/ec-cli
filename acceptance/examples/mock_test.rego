package mock_test

import rego.v1

test_mocking_ec_oci_blob if {
    ec.test.mock("ec.oci.blob", ["ref"], "wubba lubba dub dub")

    ec.oci.blob("ref") == "wubba lubba dub dub"
}
