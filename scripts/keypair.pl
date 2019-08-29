#!/usr/bin/perl

print "Enter Portfolio :";
$portfolio=<STDIN>;
chomp($portfolio);
print "Enter App: ";
$app=<STDIN>;
chomp($app);
$appName="$portfolio-$app";

print "Ensure that your STS token is from the Account that you want to create/retrieve the keypair\n";
print "Ensure https_proxy env is set\n";
print "----Menu------\n";
print "(1) Create keypair $appName\n";
print "(2) Retrieve private keypair $appName\n";
print "(3) List keypairs\n";
print "Enter Option : ";
$input=<STDIN>;

if($input =~ /1/)
{
	create_keypair();
}
elsif ($input =~ /2/)
{
	retrieve_private_keypair();
}
elsif ($input =~ /3/)
{
	list_keypairs();
}
else
{
	print "Exiting\n";
}


sub list_keypairs
{
	$rc=`aws ec2 describe-key-pairs --query 'KeyPairs[*].[KeyName]' --output text`;
	print "List of keypair found\n";
	print $rc;
}

sub retrieve_private_keypair
{
   	$pem=`aws secretsmanager get-secret-value --secret-id $appName-keypair --query 'SecretString' --output text`;
	print $pem;

}

sub create_keypair
{

	print "Creating keypair = $portfolio-$app-keypair\n";
	$pem=`aws ec2 create-key-pair --key-name $appName-keypair --query 'KeyMaterial' --output text`;

	if($pem =~ /PRIVATE KEY/)
	{

		open(FILEH,">$appName.pem");
		print FILEH $pem;
		close(FILEH);
		$rc=`aws secretsmanager create-secret --name $appName-keypair --description "Ec2 private key for $appName"  --secret-string file://$appName.pem --tags Key="Portfolio",Value="$portfolio" Key="App",Value="$app"`;
		print $rc;
		`rm $appName.pem`;
	
	}
	else
	{
		print "Error=$pem\n";
	}
}

