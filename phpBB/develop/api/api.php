<?php
/**
 *
 * @package phpBB3
 * @copyright (c) 2013 phpBB Group
 * @license http://opensource.org/licenses/gpl-2.0.php GNU General Public License v2
 *
 * Simple and fast prototype to test the API
 */

include 'client.php';


$client = new client();
$keys = @file_get_contents('keys.txt');
if (!isset($_GET['mode']))
{
	if(strlen($keys) == 0)
	{
		echo '<a href="' . $client->get_auth_link() . '">Please authenticate</a>';
	}
	else
	{
		$keyarr = explode('|', $keys);

		if ($keyarr[1] == 'null') {
			echo '<a href="?mode=exchange">Please exchange keys</a>';
		}
		else if ($keyarr[2] == 'false')
		{
			echo '<a href="?mode=verify">Please verify</a>';
		}
		else
		{
			echo '<form action="api.php" method="POST">';
			echo 'Method: <input name="method" /><br />';
			echo 'Parameters (split by |): <input name="parameters"/><br />';
			echo 'Guest: <input type="checkbox" name="guest"/><br />';
			echo '<input type="submit" /> </form>';
		}
	}

}
else if ($_GET['mode'] == 'verify')
{
	if ($client->verify())
	{
        echo '<a href="api.php">All Ok!</a><br>';
        echo '<a href="api.php?mode=refresh">Refresh your token!</a>';
	}
	else
	{
		echo '<a href="?mode=verify">Please verify : try again</a>';
	}
}
else if ($_GET['mode'] == 'exchange') {
    $client->exchange();
    echo '<a href="api.php?mode=verify">Please verify!</a>';
}
else if ($_GET['mode'] == 'refresh') {
    $client->refresh();
}

if (isset($_POST['method']))
{
	$parameters = explode('|', $_POST['parameters']);
	echo $client->request($_POST['method'], $parameters);
}
