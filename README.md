<div dir="rtl" lang="en">

# Service Monitor for Linux and Windows
.
Class Name: `security`:
  
  -this class has two main layers: 
  1. no one can get an access to the Log file while the program is running - using `portlocker` model
  2. when the user exit the program then a checksum signature added to the file (using MD5) to make sure that no one tried to modify the file content.
 
Class Name: `monitor`:
-
 this class makes a sample eny x time of all the existance services on the computer. the samples dumps to a Json file and the changes dumps to a txt file.

Class Name: `hand`:
  -
  this class comparing samples given by the User as input

</div>
