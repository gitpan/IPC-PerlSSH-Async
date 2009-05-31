#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2008 -- leonerd@leonerd.org.uk

package IPC::PerlSSH::Async;

use strict;
use warnings;
use base qw( IO::Async::Stream IPC::PerlSSH::Base );

use IO::Async::Stream;

our $VERSION = '0.04';

use Carp;

=head1 NAME

C<IPC::PerlSSH::Async> - Asynchronous wrapper around L<IPC::PerlSSH>

=head1 SYNOPSIS

I<Note:> the constructor has changed since version 0.03.

 use IO::Async::Loop;
 use IPC::PerlSSH::Async;

 my $loop = IO::Async::Loop->new();

 my $ips = IPC::PerlSSH::Async->new(
    on_exception => sub { die "Failed - $_[0]\n" },

    Host => "over.there",
 );

 $loop->add( $ips );

 $ips->eval(
    code => "use POSIX qw( uname ); uname()",
    on_result => sub { print "Remote uname is ".join( ",", @_ )."\n"; },
 );

 # We can pass arguments
 $ips->eval( 
    code => 'open FILE, ">", shift; print FILE shift; close FILE;',
    args => [ "foo.txt", "Hello, world!" ],
    on_result => sub { print "Wrote foo.txt\n" },
 );

 # We can load pre-defined libraries
 $ips->use_library(
    library => "FS",
    funcs   => [qw( unlink )],
    on_loaded => sub {
       $ips->call(
          name => "unlink",
          args => [ "foo.txt" ],
          on_result => sub { print "Removed foo.txt\n" },
       );
    },
 );

 $loop->loop_forever;

=head1 DESCRIPTION

This module provides an object class that implements the C<IPC::PerlSSH>
behaviour in an asynchronous way, suitable for use in an C<IO::Async>-based
program.

Briefly, C<IPC::PerlSSH> is a module that allows execution of perl code in a
remote perl instance, usually accessed via F<ssh>, with the notable
distinction that the module does not need to be present in the remote end, nor
does any special server need to be running, besides F<ssh> itself. For more
detail, see the L<IPC::PerlSSH> documentation.

=cut

=head1 INITIAL PARAMETERS

In order to specify the type of connection to be used, exactly one of the
following sets of keys should be passed to C<new>:

=over 8

=head2 SSH Connection

=item Host => STRING

=item User => STRING (optional)

=item SshPath => STRING (optional)

=item Perl => STRING (optional)

SSH to the given hostname, as the optionally given username. C<SshPath> and
C<Perl> are optional strings to give the local path to the F<ssh> binary, and
the remote path to the remote F<perl> respectively.

=head2 Arbitrary Command

=item Command => STRING|ARRAY

A string or ARRAY reference containing arguments to be exec()ed

=head2 Direct IO Handles

=item read_handle => IO

=item write_handle => IO

IO handles.

=back

=head1 PARAMETERS

The following named parameters may be passed to C<new> or C<configure>:

=over 8

=item on_exception => CODE

Optional. A default callback to use if a call to C<eval()>, C<store()> or
C<call()> does not provide one. If it is changed while a result it
outstanding, the handler that was in place at the time it was invoked will be
used in case of errors. Changes will only affect new C<eval()>, C<store()> or
C<call()> calls made after the change.

=back

=cut

sub new
{
   my $class = shift;
   my %args = @_;

   my $loop = delete $args{loop};

   my $self = $class->SUPER::new( %args );

   $loop->add( $self ) if $loop;

   return $self;
}

sub _init
{
   my $self = shift;
   my ( $params ) = @_;

   foreach (qw( read_handle write_handle Command Host User SshPath Perl )) {
      $self->{init_args}{$_} = delete $params->{$_} if exists $params->{$_};
   }

   return $self->SUPER::_init( $params );
}

sub configure
{
   my $self = shift;
   my %params = @_;

   if( exists $params{on_exception} ) {
      my $on_exception = delete $params{on_exception};
      !$on_exception or ref $on_exception eq "CODE"
         or croak "Expected 'on_exception' to be a CODE reference";

      $self->{on_exception} =  $on_exception;
   }

   $self->SUPER::configure( %params );
}

sub _add_to_loop
{
   my $self = shift;
   my $class = ref $self;
   my ( $loop ) = @_;

   my ( $read_handle, $write_handle );

   my $params = delete $self->{init_args} or return; # Already done it

   if( $params->{read_handle} and $params->{write_handle} ) {
      $read_handle  = $params->{read_handle};
      $write_handle = $params->{write_handle};
   }
   else {
      my @command = $self->build_command( %$params );

      # TODO: IO::Async ought to have nice ways to do this
      pipe( $read_handle, my $childwr  ) or croak "Unable to pipe() - $!";
      pipe( my $childrd, $write_handle ) or croak "Unable to pipe() - $!";

      my $pid = $loop->spawn_child(
         command => \@command,
         setup => [
            stdin  => $childrd,
            stdout => $childwr,
         ],
         on_exit => sub {
            print STDERR "Remote SSH died early";
         },
      );

      close( $childrd );
      close( $childwr );

      $self->{pid} = $pid;
   }

   $self->{message_queue} = [];

   $self->configure(
      read_handle  => $read_handle,
      write_handle => $write_handle,
   );

   $self->send_firmware;
}

sub on_read
{
   my $self = shift;
   my ( $buffref, $closed ) = @_;

   return 0 if $closed;

   my ( $message, @args ) = $self->parse_message( $$buffref );
   return 0 unless defined $message;

   my $cb = shift @{ $self->{message_queue} };
   $cb->( $message, @args );

   return 1;
}

sub do_message
{
   my $self = shift;
   my %args = @_;

   my $message = $args{message};
   my $args    = $args{args};

   my $on_response = $args{on_response};
   ref $on_response eq "CODE" or croak "Expected 'on_response' as a CODE reference";

   $self->write_message( $message, @$args );

   push @{ $self->{message_queue} }, $on_response;
}

=head1 METHODS

=cut

=head2 $ips->eval( %args )

This method evaluates code in the remote host, passing arguments and returning
the result.

The C<%args> hash takes the following keys:

=over 8

=item code => STRING

The perl code to execute, in a string. (i.e. NOT a CODE reference).

=item args => ARRAY

Optional. An ARRAY reference containing arguments to pass to the code.

=item on_result => CODE

Continuation to invoke when the code returns a result.

=item on_exception => CODE

Optional. Continuation to invoke if the code throws an exception.

=back

The code should be passed in a string, and is evaluated using a string
C<eval> in the remote host, in list context. If this method is called in
scalar context, then only the first element of the returned list is returned.
Only string scalar values are supported in either the arguments or the return
values; no deeply-nested structures can be passed.

To pass or return a more complex structure, consider using a module such as
L<Storable>, which can serialise the structure into a plain string, to be
deserialised on the remote end.

If the remote code threw an exception, then this function propagates it as a
plain string.

=cut

sub eval
{
   my $self = shift;
   my %args = @_;

   my $code = $args{code};
   my $args = $args{args};

   my $on_result = $args{on_result};
   ref $on_result eq "CODE" or croak "Expected 'on_result' as a CODE reference";

   my $on_exception = $args{on_exception} || $self->{on_exception};
   ref $on_exception eq "CODE" or croak "Expected 'on_exception' as a CODE reference";

   $self->do_message(
      message => "EVAL",
      args    => [ $code, $args ? @$args : () ],

      on_response => sub {
         my ( $ret, @args ) = @_;

         if( $ret eq "RETURNED" ) { $on_result->( @args ); }
         elsif( $ret eq "DIED" )  { $on_exception->( $args[0] ); }
         else                     { warn "Unknown return result $ret"; }
      },
   );
}

=head2 $ips->store( %args )

This method sends code to the remote host to store in a named procedure which
can be executed later.

The C<%args> hash takes the following keys:

=over 8

=item name => STRING

A name for the stored procedure.

=item code => STRING

The perl code to store, in a string. (i.e. NOT a CODE reference).

=item on_stored => CODE

Continuation to invoke when the code is successfully stored.

=item on_exception => CODE

Optional. Continuation to invoke if compiling the code throws an exception.

=back

The code should be passed in a string, along with a name which can later be
called by the C<call> method.

While the code is not executed, it will still be compiled into a CODE
reference in the remote host. Any compile errors that occur will still invoke
the C<on_exception> continuation.

=cut

sub store
{
   my $self = shift;
   my %args = @_;

   my $name = $args{name};
   my $code = $args{code};

   my $on_stored = $args{on_stored};
   ref $on_stored eq "CODE" or croak "Expected 'on_stored' as a CODE reference";

   my $on_exception = $args{on_exception} || $self->{on_exception};
   ref $on_exception eq "CODE" or croak "Expected 'on_exception' as a CODE reference";

   $self->do_message(
      message => "STORE",
      args    => [ $name, $code ],

      on_response => sub {
         my ( $ret, @args ) = @_;

         if( $ret eq "OK" )      { $on_stored->(); }
         elsif( $ret eq "DIED" ) { $on_exception->( $args[0] ); }
         else                    { warn "Unknown return result $ret"; }
      },
   );
}

=head2 $ips->call( %args )

This method invokes a stored procedure that has earlier been defined using the
C<store> method. The arguments are passed and the result is returned in the
same way as with the C<eval> method.

The C<%params> hash takes the following keys:

=over 8

=item name => STRING

The name of the stored procedure.

=item args => ARRAY

Optional. An ARRAY reference containing arguments to pass to the code.

=item on_result => CODE

Continuation to invoke when the code returns a result.

=item on_exception => CODE

Optional. Continuation to invoke if the code throws an exception.

=back

=cut

sub call
{
   my $self = shift;
   my %args = @_;

   my $name = $args{name};
   my $args = $args{args};

   my $on_result = $args{on_result};
   ref $on_result eq "CODE" or croak "Expected 'on_result' as a CODE reference";

   my $on_exception = $args{on_exception} || $self->{on_exception};
   ref $on_exception eq "CODE" or croak "Expected 'on_exception' as a CODE reference";

   $self->do_message(
      message => "CALL",
      args    => [ $name, $args ? @$args : () ],

      on_response => sub {
         my ( $ret, @args ) = @_;

         if( $ret eq "RETURNED" ) { $on_result->( @args ); }
         elsif( $ret eq "DIED" )  { $on_exception->( $args[0] ); }
         else                     { warn "Unknown return result $ret"; }
      },
   );
}

=head2 $ips->use_library( %args )

This method loads a library of code from a module, and stores them to the
remote perl by calling C<store> on each one.

The C<%params> hash takes the following keys:

=over 8

=item library => STRING

Name of the library to load

=item funcs => ARRAY

Optional. Reference to an array containing names of functions to load.

=item on_loaded => CODE

Continuation to invoke when all the functions are stored.

=item on_exception => CODE

Optional. Continuation to invoke if storing a function throws an exception.

=back

The library name may be a full class name, or a name within the
C<IPC::PerlSSH::Library::> space.

If the funcs list is non-empty, then only those named functions are stored
(analogous to the C<use> perl statement). This may be useful in large
libraries that define many functions, only a few of which are actually used.

For more information, see L<IPC::PerlSSH::Library>.

=cut

sub use_library
{
   my $self = shift;
   my %args = @_;

   my $library = $args{library};
   my $funcs   = $args{funcs};

   my $on_loaded = $args{on_loaded};
   ref $on_loaded eq "CODE" or croak "Expected 'on_loaded' as a CODE reference";

   my $on_exception = $args{on_exception} || $self->{on_exception};
   ref $on_exception eq "CODE" or croak "Expected 'on_exception' as a CODE reference";

   my %funcs = eval { $self->load_library( $library, $funcs ? @$funcs : () ) };
   if( $@ ) {
      $on_exception->( $@ );
      return;
   }

   my $iter; $iter = sub {
      if( !%funcs ) {
         undef $iter; # Avoid circular ref which would otherwise hold $self
         goto &$on_loaded;
      }

      my ( $name ) = ( keys %funcs ); # Just take one
      my $code = delete $funcs{$name};

      $self->store(
         name => $name,
         code => $code,
         on_stored => $iter,
         on_exception => sub { undef $iter; goto &$on_exception },
      );
   };

   $iter->();
}

sub DESTROY
{
   my $self = shift;

   # Be safe at global destruction time
   $self->{stream}->close if defined $self->{stream};
}

# Keep perl happy; keep Britain tidy
1;

__END__

=head1 AUTHOR

Paul Evans E<lt>leonerd@leonerd.org.ukE<gt>
