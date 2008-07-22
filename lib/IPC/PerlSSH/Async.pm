#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2008 -- leonerd@leonerd.org.uk

package IPC::PerlSSH::Async;

use strict;
use base qw( IPC::PerlSSH::Base );

use IO::Async::Stream;

our $VERSION = '0.01';

use Carp;

=head1 NAME

C<Net::Async::IPC::PerlSSH> - Asynchronous wrapper around L<IPC::PerlSSH>

=head1 SYNOPSIS

=head1 DESCRIPTION

=cut

=head1 CONSTRUCTOR

=cut

sub new
{
   my $class = shift;
   my %args = @_;

   my $loop = delete $args{loop} or croak "Need a 'loop'";

   !$args{on_exception} or ref $args{on_exception} eq "CODE"
      or croak "Expected 'on_exception' to be a CODE reference";

   my @messagequeue;

   my $self = bless {
      on_message_queue => \@messagequeue,
      loop => $loop,
      on_exception => $args{on_exception},
   }, $class;

   my ( $read_handle, $write_handle );

   if( $args{read_handle} and $args{write_handle} ) {
      $read_handle  = $args{read_handle};
      $write_handle = $args{write_handle};
   }
   else {
      my @command = $self->build_command( %args );

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

   $self->{stream} = IO::Async::Stream->new(
      read_handle  => $read_handle,
      write_handle => $write_handle,

      on_read => sub {
         my ( $stream, $buffref, $closed ) = @_;

         return 0 if $closed;

         return 0 unless my ( $message, @args ) = $class->parse_message( $$buffref );

         my $cb = shift @messagequeue;
         $cb->( $message, @args );

         return 1;
      },
   );

   $self->send_firmware;

   $loop->add( $self->{stream} );

   return $self;
}

sub write
{
   my $self = shift;
   my ( $data ) = @_;

   # During DESTROY, stream will actually be the outbound IO handle directly
   $self->{stream}->write( $data );
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

   push @{ $self->{on_message_queue} }, $on_response;
}

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
         else                     { carp "Unknown return result $ret"; }
      },
   );
}

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
         else                    { carp "Unknown return result $ret"; }
      },
   );
}

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
         else                     { carp "Unknown return result $ret"; }
      },
   );
}

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

   # Major cheating
   my $stream = $self->{stream};

   $self->{stream} = $stream->write_handle;

   $self->SUPER::DESTROY;

   $self->{loop}->remove( $stream );

   undef $self->{stream};
   undef $self->{loop};
}

# Keep perl happy; keep Britain tidy
1;

__END__

=head1 AUTHOR

Paul Evans E<lt>leonerd@leonerd.org.ukE<gt>
