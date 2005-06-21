use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'TDB_File',
    'VERSION_FROM'	=> 'TDB_File.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'TDB_File.pm', # retrieve abstract from module
       AUTHOR     => 'Angus Lees <gus@inodes.org>') : ()),
    'XSPROTOARG'	=> '-prototypes',
    'LIBS'		=> ['-ltdb'],
    #'OPTIMIZE'		=> '-g -Wall',
    'clean'		=> {FILES => "t/test.tdb"},
);

if (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
  my @names = (qw(TDB_REPLACE TDB_INSERT TDB_MODIFY
		  TDB_DEFAULT TDB_CLEAR_IF_FIRST TDB_INTERNAL TDB_NOLOCK
		  TDB_NOMMAP TDB_CONVERT TDB_BIGENDIAN),
	       # these are an enum, so not #ifdef-able:
	       map({ {name => $_, macro => 1} }
		   qw(TDB_SUCCESS TDB_ERR_CORRUPT TDB_ERR_IO TDB_ERR_LOCK
		      TDB_ERR_OOM TDB_ERR_EXISTS TDB_ERR_NOLOCK
		      TDB_ERR_LOCK_TIMEOUT TDB_ERR_NOEXIST
		     )));

  ExtUtils::Constant::WriteConstants(NAME => 'TDB_File',
				     NAMES => \@names,
				     DEFAULT_TYPE => 'IV',
				     C_FILE => 'const-c.inc',
				     XS_FILE => 'const-xs.inc',
				    );
}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}


# extra test targets. useful with stop() macro in TDB_File.xs
# (copied from Embperl Makefile.PL (thanks Gerald))
sub MY::test {
  my ($txt) = shift->MM::test(@_);

  $txt .= <<EOF;

testdbinit : pure_all
\t\@echo set args -I\$(INST_ARCHLIB) -I\$(INST_LIB) -I\$(PERL_ARCHLIB) -I\$(PERL_LIB) \$(TEST_FILE) \$(TESTARGS) > testdbinit

testdbbreak : pure_all
\t\@echo set args -I\$(INST_ARCHLIB) -I\$(INST_LIB) -I\$(PERL_ARCHLIB) -I\$(PERL_LIB) \$(TEST_FILE) --dbgbreak \$(TESTARGS) > testdbbreak
\t\@echo r >> testdbbreak

testgdb : testdbinit
\tPERL_DL_NONLAZY=1 gdb -x testdbinit \$(FULLPERL)

testgdbb : testdbbreak
\tPERL_DL_NONLAZY=1 gdb -x testdbbreak \$(FULLPERL)

EOF

  return $txt ;
}
