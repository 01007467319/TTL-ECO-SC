pragma solidity ^0.4.16;

//in order to invoke function 'producing' in the contract 'interfaceProducing',
//this dedines an interface 'interfaceProducing'.
interface interfaceProducing 
{
    function producing(bytes32 block_header, uint k)  external returns(uint, uint, uint);

}

//this dedines an interface 'interfaceArbitration'.
//providing function 'arbitration'.
interface interfaceArbitration
{
    function arbitration(address addr, bytes32 block_header, uint k, bytes32 k_i, bytes32 c_i, bytes32 w_i, bytes32 d_des_i) public returns(bool);
}

//this is a arbitration contract 'interfaceArbitration'
 contract Arbitration is interfaceArbitration{
   
    //defining an arbitrator array   
    uint[5] arbitrators;
    uint value = 0;
    
    function arbitration(
                          address addr,           //invoked contract 'InterfaceProducing' address 
                          bytes32 block_header,   //block_header is the first parameter of the function producing in the contract 'InterfaceImplProducing' 
                          uint k,                 //arbitration number 'k'
                          bytes32 k_i,            //the data key 'k_i' of the data segment i 
                          bytes32 c_i,             //ciphertext for data segment 'd_i'
                          bytes32 w_i,            //the ciphertext 'w_i' of the data key 'k_i'
                          bytes32 d_des_i        //the description of the i-th data segment
                          ) 
                          public returns(bool)    //return arbitration result 'true' denoting seller success, or 'false' denoting buyer success

    {
       
       //finding contract 'interfaceProducing' by inputting contract address 'addr'.
       interfaceProducing _interfaceProducing = interfaceProducing(addr);
       
       //obtaining some arbitrators through invoking contract 'interfaceProducing'.
       //this use arbitrators[i] to represent an arbitrator, since the Solidity does not provide API of mapping
       //about the relation between the miner(arbitrator) and the block.
       (arbitrators[0], arbitrators[1], arbitrators[2]) = _interfaceProducing.producing(block_header, k); 
       
       
       //showing vote result of each arbitrators[i] 
       for (uint i = 0; i < k; i ++ )
       {
          if (vote(arbitrators[i], d_des_i, w_i, k_i, c_i) == 1)
          {
              value = value + 1;
          }
          else if (vote(arbitrators[i], d_des_i, w_i, k_i, c_i) == 0)
          {
              value = value - 1;
          }
          
       }
       
       //declaring arbitration result 
       if(value > 0)
       {
           return (true);
       }
       else
       {
           return (false);
       }

    }
    
    //each arbitrator 'arbitrators[i]' is voting.
    //this subsitutes 'd_des_i = DPKE.Enc_pk(k_i)' with 'd_des_i == d_des_i', 
    //since the Solidity does not provide API of the DPEK.Enc().
    //similarly, this subsitutes 'D_des_i = AES.Dec_{k_i}k(c_i)' with 'w_i == w_i',
    //'c_i = c_i', 'k_i == k_i'.
    function vote (uint val2, bytes32 d_des_i, bytes32 w_i, bytes32 k_i, bytes32 c_i) returns(uint)        
    {
        
        //whether judging arbitrator 'arbitrators[i]' is true.
        require(val2 == val2);

        if (d_des_i == d_des_i)
           {
               if (w_i == w_i)
               {
                   if (k_i == k_i)
                   {
                       if (c_i == c_i)
                       {
                          return 1;        
                       }
                       else
                       {
                           return 0;
                       }
                   }
                   else
                   {
                       return 0;
                   }
               }
               else
               {
                   return 0;
               }
           }
           else
           {
               return 0;
           } 
    }
    

}
