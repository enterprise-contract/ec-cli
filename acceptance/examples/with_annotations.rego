package policy.release.kitty

# METADATA
# title: Kittens
# description: Fluffy
# custom:
#   short_name: purr
#
deny contains result if {
    result := "Meow"
}
