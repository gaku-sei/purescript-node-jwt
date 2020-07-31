{ name = "node-jwt"
, license = "MIT"
, repository = "https://github.com/gaku-sei/purescript-node-jwt"
, dependencies =
  [ "aff"
  , "aff-promise"
  , "console"
  , "effect"
  , "foreign-generic"
  , "generics-rep"
  , "newtype"
  , "psci-support"
  , "options"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs" ]
}
