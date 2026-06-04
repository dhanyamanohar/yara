rule 
{
	meta:
		author = "test"
	strings:
		$lure1 = "Job Description" ascii
		$lure2 = "Job Vacancies" ascii

	condition:
		and filesize < 2MB
		and 1 of them

}
