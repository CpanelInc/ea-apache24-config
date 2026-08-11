#!/usr/local/cpanel/3rdparty/bin/perl

# cpanel - t/SOURCES-cptechdomain.t                  Copyright 2026 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use Test::More tests => 3 + 1;
use Test::NoWarnings;

use FindBin;
use File::Slurp 'read_file';

my $shtml = "$FindBin::Bin/../SOURCES/cptechdomain.shtml";

ok( -f $shtml, "cptechdomain.shtml exists" );

my $content = read_file($shtml);

# EA4-294: mod_include's #echo defaults to encoding="entity", which turns '&' into
# '&amp;'. HTML entities are never decoded inside a JavaScript string literal, so
# templating a URI into JS renames every query parameter after the first. Entity
# encoding also leaves "'" unescaped, making it an XSS vector in a single-quoted
# string. Nothing SSI belongs inside <script>.
my @offending;
while ( $content =~ m{<script[^>]*>(.*?)</script>}gis ) {
    my $js = $1;
    push @offending, $js if $js =~ m{<!--\s*#\s*echo}i;
}
is_deeply( \@offending, [], "no SSI #echo inside any <script> block (EA4-294)" );

# The Continue button must resume the request without templating the URL at all.
like(
    $content,
    qr{window\.location\.reload\(\)},
    "Continue handler resumes via window.location.reload()",
);
