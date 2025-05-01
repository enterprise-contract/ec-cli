package kitty

import rego.v1

# METADATA
# title: Kittens
# description: Fluffy
# custom:
#   short_name: purr
#
deny contains result if {
    result := "Meow"
}
