package Cpanel::Template::Plugin::ApacheConfig;

#                                      Copyright 2025 WebPros International, LLC
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited.

use cPstrict;
use Cpanel::Imports;

use parent 'Template::Plugin';

use Cpanel::HTTP::Client ();
use Cpanel::JSON         ();

=encoding utf-8

=head1 NAME

Cpanel::Template::Plugin::ApacheConfig - Template Toolkit plugin for Apache Configuration Files

=head1 SYNOPSIS

    [% USE ApacheConfig %]

    [% ApacheConfig.generate_cloudflare_config() %]

=cut

=head2 new

Returns a 'Cpanel::Template::Plugin::ApacheConfig' object.

=cut

sub new ( $class, $context, @args ) {
    my $plugin = { _CONTEXT => $context, templates_dir => '/var/cpanel/templates/apache2_4' };
    bless $plugin, $class;
    return $plugin;
}

=head2 generate_cloudflare_config()

This method retrieves Cloudflare IP ranges for use with relevant Apache configuration files.

Returns a boolean marking a successful operation.

=cut

sub generate_cloudflare_config ($self) {
    my $template_file = $self->{templates_dir} . '/cloudflare.tt';
    my $output_path   = '/etc/apache2/conf.d/includes/cloudflare.conf';
    my $permissions   = 0600;

    my $res = Cpanel::HTTP::Client->new()->get("https://api.cloudflare.com/client/v4/ips");
    if ( !$res->{success} ) {
        logger()->error("Could not GET Cloudflare IPs ($res->{status} $res->{reason})");
        return 0;
    }

    my $data = Cpanel::JSON::Load( $res->{content} );

    my $etag = $data->{result}{etag} // "none";
    my ( $ipv4_cidrs, $ipv6_cidrs ) = $data->{result}->@{ 'ipv4_cidrs', 'ipv6_cidrs' };

    my $time = localtime();
    require Cpanel::Template;
    my ( $success, $output ) = Cpanel::Template::process_template(
        'cloudflare_ips',
        {
            template_file => $template_file,
            print         => 0,

            gen_time   => $time,
            etag       => $etag,
            ipv4_cidrs => $ipv4_cidrs,
            ipv6_cidrs => $ipv6_cidrs,
        },
        {},
    );
    if ( !$success ) {
        logger()->error("Could not process template $template_file: $output");
        return 0;
    }

    # Write new configuration file
    my $txn = Cpanel::Transaction::File::Raw->new( path => $output_path, permissions => $permissions );
    $txn->set_data($output);
    my ( $ok, $msg ) = $txn->save_and_close();

    if ( !$ok ) {
        logger()->error("Unable to write $output_path [$msg]: $!");
        return 0;
    }

    return 1;
}

1;
