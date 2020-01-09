pragma solidity ^0.4.16;

//in order to invoke function 'arbitration' in the arbitration contract 'interfaceArbitration',
//this dedines an interface 'interfaceArbitration'.
interface interfaceArbitration 
{
   function arbitration(address addr, bytes32 ran_num, uint k, bytes32 k_i, bytes32 c_i, bytes32 w_i, bytes32 d_des_i) public returns(bool);
}

//this is a sale contract 'sale'
 contract Sale{
 
    struct Buyer 
   {
       
        uint money;         // the money of the data segment to be purphased
        uint deposit_b;    // the deposit of the buyer
        bytes32 pk;        // the public key pk of the buyer 
        uint    i;         // the index i about the data i to be purphased
        address buyer;     // the address of the buyer 

    }    
    
   //a seller struct 
   struct Seller 
   {
       
        uint deposit_s;    // the deposit and the payment for data
        bytes32 w;         // the ciphertext w_i of the data key k_i   
        address seller;    // the address of the Seller 

    }     
    
    // stores a `Buyer` struct for each possible buyer.
    mapping(address => Buyer) public buyers;
    
    // stores a `Seller` struct
    mapping(address => Seller) public sellers;
    
    //define a threshold ‘t’
    uint t = 3 ether;
    
    address sel_d;
    address buy_d;
    
    //define time of the contract creating
    uint public createTime = now;
    
   //the seller deposits the deposit and the money to the contract address when the seller creates the sale contract
   function deposit_seller() public payable 
   {  

      sellers[msg.sender].deposit_s = msg.value;   
      sellers[msg.sender].seller  = msg.sender;
      sel_d = msg.sender;
      
   }
    
   //the buyer deposits the deposit and the money to the address of the contract 
   //the buyer adds the deposit if the buyer's deposit is insufficient
   //the buyer adds the money if the buyer's money is insufficient
   function deposit_buyer() public payable 
   {  

      buyers[msg.sender].buyer  = msg.sender;
      buy_d = msg.sender;
      
      if (msg.value >= t)
      {
         if (buyers[msg.sender].deposit_b >= t)
         {
            buyers[msg.sender].money = buyers[msg.sender].money + msg.value; 
         }
         else if (buyers[msg.sender].deposit_b < t)
         {
            buyers[msg.sender].money = msg.value - t;
            buyers[msg.sender].deposit_b = msg.value - buyers[msg.sender].money; 
         }
         
      }
      else if (msg.value < t)
      {
         if (buyers[msg.sender].deposit_b >= t)
         {
            buyers[msg.sender].money = buyers[msg.sender].money + msg.value; 
         }
         else if (buyers[msg.sender].deposit_b < t)
         {
            buyers[msg.sender].deposit_b = buyers[msg.sender].deposit_b + msg.value;   
         }
         
      }
      
   }
   
    //the buyer updates his 'pk' and the index 'i' of the data 
    function deposit_buyerdata(bytes32 pk, uint i) public 
    {

       buyers[msg.sender].pk = pk;  
       buyers[msg.sender].i = i;   
       
    }   
   
   //reveal the balance of the contract address 
   function getBalance() constant returns (uint)
   {
       return this.balance;
   }
   
    
    //if one party has insufficient deposit，another party withdraws his deposit.
    function withdraw() public returns (bool)  
    {

       uint value1 = sellers[msg.sender].deposit_s; 
       uint value2 = buyers[msg.sender].deposit_b; 
       uint value3 = buyers[msg.sender].money; 
       
       //the buyer withdraws his deposit and money if the seller's deposit is insufficient
       if ((buyers[msg.sender].buyer == msg.sender) && (sellers[sel_d].deposit_s < t))
       {
           
          buyers[msg.sender].deposit_b = 0;
          msg.sender.transfer(value2);
          
          buyers[msg.sender].money = 0;
          msg.sender.transfer(value3);
          
          return (true);
          
       }
       //the seller withdraws his deposit if the buyer'deposit is insufficient
       else if((sellers[msg.sender].seller == msg.sender) && (buyers[buy_d].deposit_b < t))
       {
           
          sellers[msg.sender].deposit_s = 0;
          msg.sender.transfer(value1);
          
          return (false);
          
       }
       
    }
   
   //the seller updates the ciphertext 'w' and the merkle root 'root_mer' 
   function payment_sellerdata(bytes32 w) public
   {
       
      //whether the buyer's deposit exceeds the threshold t, 
      require((buyers[buy_d].deposit_b >= t) && (buyers[buy_d].deposit_b != 0)); 
          
      sellers[msg.sender].w = w;   

    }        
    
    //the buyer provides transaction application. 
    //the buyer provides true if the buyer believes the data transaction is fair.
    //the buyer obtains the data and the deposit returned by the sale contract. 
    //the seller gains the money and deposit returned by the sale contract, when the data transaction is fair.
    function payment_transaction(bool t_or_f) public  returns (bool)
    {
        
        uint value4 = sellers[sel_d].deposit_s; 
        uint value5 = buyers[buy_d].deposit_b; 
        uint value6 = buyers[buy_d].money; 
       
        if (t_or_f == true)
        {
          sellers[sel_d].deposit_s = 0;
          sel_d.transfer(value4);
          
          buyers[buy_d].deposit_b = 0;
          buy_d.transfer(value5);
          
          buyers[buy_d].money = 0;
          sel_d.transfer(value6);
          
          return (true);
        }
        //if the buyer does not submit application within the specified time (i.e., 1 hours),
        //the contract will automatically implement refunding action.
        else if (now >= createTime + 1 hours)
        {
          
          sellers[sel_d].deposit_s = 0;
          sel_d.transfer(value4);
          
          buyers[buy_d].deposit_b = 0;
          buy_d.transfer(value5);
          
          buyers[buy_d].money = 0;
          sel_d.transfer(value6);
          
          return (true);
            
        }
        
    }

    //the buyer applies arbitration, when the buyer believes the data transaction is unfair.
    //both the seller and the buyer are provide arbitration data such as arbitration contract address 'addre',
    //producing contract address 'addr', 'ran_num', arbitration number 'k', the data key 'k_i', publi key 'pk',
    //the ciphertext 'w_i' of the data key 'k_i', merkle verification path 'path_mer'.
    function arbitration_invoke(address addre,address addr, bytes32 ran_num, uint k, bytes32 k_i,  bytes32 c_i, bytes32 w_i, bytes32 d_des_i) returns(bool, uint)    
    {

       bool u1;
       
       //defining the buyer's money
       uint value7 = buyers[buy_d].money;  
       
       //finding contract 'interfaceArbitration' by inputting contract address 'addre'.
       interfaceArbitration _interfaceArbitration = interfaceArbitration(addre);
       
       //obtaining arbitration result 'u1' through invoking function 'arbitration' 
       //in the arbitration contract 'interfaceArbitration'.
       u1 = _interfaceArbitration.arbitration(addr, ran_num, k, k_i, c_i, w_i, d_des_i); 
       
       //if u1 is 'true' denoting the seller success, the contract confiscates the buyer's deposit,
       //refunds the seller's deposit and the money to the seller.
       //note that the confiscated buyer's deposit is deposited into the seller account,
       //other than the arbitrator account. since the Solidity does not provide API of mapping
       //about the relation between the miner(arbitrator) and the block.
       if (u1 == true)
       {
          sellers[sel_d].deposit_s = 0;
          sel_d.transfer(3 ether);
          
          buyers[buy_d].deposit_b = 0;
          sel_d.transfer(3 ether);
          
          buyers[buy_d].money = 0;
          sel_d.transfer(value7);
           
          return (true, value7);
          
       }
       //if u1 is 'false' denoting the buyer success, the contract confiscates the seller's deposit,
       //refunds the buyer's deposit and the money to the buyer.
       //note that the confiscated seller's deposit is deposited into the buyer account,
       //other than the arbitrator account. since the Solidity does not provide API of mapping
       //about the relation between the miner(arbitrator) and the block.
       else if (u1 == false)
       {
          sellers[sel_d].deposit_s = 0;
          buy_d.transfer(3 ether);
          
          buyers[buy_d].deposit_b = 0;
          buy_d.transfer(3 ether);
          
          buyers[buy_d].money = 0;
          buy_d.transfer(value7);
          
          return (false, value7);
 
       }
    
    }
    
}
