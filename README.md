**OvS** with added security functionalities:
  1. SYN sketch block -> mitigate SYN repeat < 1s and SYN random flood
  2. Conditional add_blocking_flow -> mitigate SYN repeat > 1s flood 
  3. new OvS to controller asynchronous message -> To inform controller of SYN flood occurence

<br>
<br>

![BS_SDN_new](https://github.com/Hieu-personal-project/OvS_3.0.9_BS-SDN/assets/43841523/66a8e34c-01d0-4a15-b277-b0b14222092f)

<br>
**BS-SDN** uses probabilistic data structure call Count-min Sketch and leverage bit-marking algorithm to mitigate SYN flood

<br>
<br>


![h6_cms](https://github.com/Hieu-personal-project/OvS_3.0.9_BS-SDN/assets/43841523/2f04d36f-6e34-4b00-85b7-e34b3beb9d13)
