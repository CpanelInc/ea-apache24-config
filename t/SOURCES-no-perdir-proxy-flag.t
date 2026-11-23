#!/usr/local/cpanel/3rdparty/bin/perl

# cpanel - t/SOURCES-no-perdir-proxy-flag.t   Copyright 2026 WebPros International, LLC
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited.

# EA4-418 guard: the ea-apache24 patch "Block [P] in per-directory context"
# makes mod_rewrite refuse the [P] (proxy) flag BY DEFAULT when a RewriteRule is
# evaluated in per-directory context (.htaccess, <Directory>, <Location>,
# <Files>, and their *Match variants), returning 403. Any Apache template shipped
# here that placed a [P] RewriteRule in such a context would start 403'ing after
# that patch. This test fails if any SOURCES template emits a [P] RewriteRule in a
# per-directory container (or a .htaccess), so the regression is caught before it
# ships. cPanel's own proxy rules (service subdomains, autodiscover/autoconfig)
# live at <VirtualHost>/server scope and are unaffected -- this test proves that
# stays true.
#
# NOTE: these templates are Template-Toolkit, so container tags can appear in
# alternative [% IF %]/[% ELSE %] branches (e.g. the whm-server-status <Location>).
# We strip [% ... %] and RESET the per-dir container stack at every <VirtualHost>
# boundary -- Apache containers never cross a vhost boundary -- which keeps any
# main-server TT-branch imbalance from leaking into the vhost scope where the [P]
# rules actually live. A render-based check (see SOURCES-ssl_vhost_proxysub.t for
# the Cpanel::Template pattern) is the heavier belt-and-suspenders complement.

use strict;
use warnings;

use FindBin;
use Test::More;
use Test::NoWarnings;

my @PERDIR = qw( Directory DirectoryMatch Location LocationMatch Files FilesMatch );
my $PERDIR_RE = join '|', @PERDIR;

sub _trim { my $s = shift // ''; $s =~ s/^\s+//; $s =~ s/\s+$//; return $s }

# A mod_rewrite proxy-flag rule? Matches [P] [P,L] [NC,P] [QSA,P,L];
# excludes the unrelated [PT] passthrough flag.
sub _is_proxy_rule {
    my $l = shift;
    return 0 unless $l =~ /RewriteRule/;
    return 0 unless $l =~ /\[[^\]]*P[,\]]/;
    return 0 if     $l =~ /\[[^\]]*PT[,\]]/;
    return 1;
}

# Return the list of { line, rule, ctx } per-directory [P] violations in one text.
sub scan_text {
    my ( $text, %opt ) = @_;
    my $is_htaccess = $opt{is_htaccess} ? 1 : 0;
    my @stack;
    my @violations;
    my $ln = 0;

    for my $raw ( split /\n/, $text, -1 ) {
        $ln++;
        ( my $l = $raw ) =~ s/\[%.*?%\]//g;    # drop TT directives, keep literal Apache

        if ( $l =~ /<\s*VirtualHost\b/i || $l =~ m{<\s*/\s*VirtualHost\s*>}i ) {
            @stack = ();
            next;
        }
        if ( $l =~ m{<\s*/\s*($PERDIR_RE)\s*>}i ) {
            pop @stack if @stack;
            next;
        }
        if ( $l =~ /<\s*($PERDIR_RE)\b[^>]*>/i ) {
            push @stack, lc $1;
            next;
        }
        if ( _is_proxy_rule($l) && ( $is_htaccess || @stack ) ) {
            push @violations,
              { line => $ln, rule => _trim($raw), ctx => ( $is_htaccess ? '.htaccess' : $stack[-1] ) };
        }
    }
    return @violations;
}

# ---- locate shipped templates ---------------------------------------------

my $src = "$FindBin::Bin/../SOURCES";
my @files = sort grep { -f $_ } glob("$src/*.default $src/*.tmpl");
push @files, grep { -f $_ } glob("$src/.htaccess $src/*/.htaccess");

plan tests => 6 + scalar(@files) + 1;    # 1 sanity + 5 self-tests + per-file + Test::NoWarnings

# ---- self-test: scanner is both green-correct and catches the bad case -----

my $GOOD = <<'EOF';
<VirtualHost *:80>
    <Proxy "*"></Proxy>
    <Directory "/"></Directory>
    RewriteEngine On
    RewriteRule ^/(.*) http://127.0.0.1:2082/$1 [P]
    RewriteRule ^ http://127.0.0.1/cgi-sys/autodiscover.cgi [P]
</VirtualHost>
EOF

my $GOOD_TT = <<'EOF';
<IfModule status_module>
[% IF whm_server_status_key -%]
    <Location /[% whm_server_status_key %]>
[% ELSE -%]
    <Location /whm-server-status>
[% END -%]
        SetHandler server-status
    </Location>
</IfModule>
<VirtualHost *:443>
    <Directory "/"></Directory>
    RewriteRule ^/(.*) https://127.0.0.1:2083/$1 [P]
</VirtualHost>
EOF

my $BAD_DIR = <<'EOF';
<VirtualHost *:80>
    <Directory "/home/u/public_html">
        RewriteRule ^(.*)$ unix:/other.sock|fcgi://localhost/$1 [P]
    </Directory>
</VirtualHost>
EOF

my $BAD_LOC = <<'EOF';
<VirtualHost *:80>
    <Location "/x">
        RewriteRule ^ http://127.0.0.1:9000/ [P,L]
    </Location>
</VirtualHost>
EOF

is( scalar( scan_text($GOOD) ),    0, 'self: vhost-scope [P] is not flagged' );
is( scalar( scan_text($GOOD_TT) ), 0, 'self: TT-branch <Location> does not false-positive' );
is( scalar( scan_text($BAD_DIR) ), 1, 'self: [P] inside <Directory> is flagged' );
is( scalar( scan_text($BAD_LOC) ), 1, 'self: [P,L] inside <Location> is flagged' );
is( ( scan_text( "RewriteRule ^ http://127.0.0.1/x [P]\n", is_htaccess => 1 ) )[0]{ctx},
    '.htaccess', 'self: htaccess [P] is flagged as .htaccess context' );

# ---- real scan ------------------------------------------------------------

ok( scalar(@files) >= 1, "found Apache templates under SOURCES (@{[ scalar @files ]})" );

for my $file (@files) {
    open my $fh, '<', $file or do { fail("open $file: $!"); next };
    local $/;
    my $text = <$fh>;
    close $fh;
    my $is_ht = ( $file =~ m{/\.htaccess$} ) ? 1 : 0;
    my @v = scan_text( $text, is_htaccess => $is_ht );
    ( my $short = $file ) =~ s{.*/SOURCES/}{SOURCES/};
    diag("  $short:$_->{line}  [in <$_->{ctx}>]  $_->{rule}") for @v;
    ok( !@v, "no per-directory [P] in $short" );
}
