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
