package store

// V030Migrations are the migrations a v0.3.0 binary applied, for the
// upgrade test in package store_test, which needs the approval package
// (and so cannot live in package store without an import cycle).
var V030Migrations = migrations[:4]
