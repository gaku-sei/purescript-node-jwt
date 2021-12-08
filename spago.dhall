{ name = "node-jwt"
, license = "MIT"
, repository = "https://github.com/gaku-sei/purescript-node-jwt"
, dependencies =
  [ "aff"
  , "aff-promise"
  , "bifunctors"
  , "contravariant"
  , "control"
  , "datetime"
  , "effect"
  , "either"
  , "foldable-traversable"
  , "foreign"
  , "foreign-generic"
  , "functions"
  , "integers"
  , "lists"
  , "maybe"
  , "newtype"
  , "options"
  , "prelude"
  , "psci-support"
  , "transformers"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs" ]
}
