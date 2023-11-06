# T2Labredes

O trabalho consiste em duas partes:
1. encontrar ferramentas que façam ataques explorando vulnerabilidades de
protocolos da pilha TCP/IP;
2. desenvolver um sniffer para a detecção dos ataques realizados.

   
Para o desenvolvimento da parte 1, será necessário realizar um estudo para identificar
exemplos de ataques que podem ser utilizados com a pilha TCP/IP (exploram alguma
vulnerabilidade da pilha). A turma irá escolher dois tipos de ataques e cada grupo
deve escolher ferramentas que implementem os ataques. É necessário fazer um
relatório sobre o funcionamento das ferramentas escolhidas.

## Foram escolhidos os ataques DOS e SYN Flood


Parte 2
O sniffer deve ser desenvolvido com socket raw e deve apresentar as informações
sobre o tráfego no terminal do sistema operacional. Além da detecção dos ataques
realizados, será necessário apresentar as seguintes informações no terminal:
- Nível de Enlace
- Quantidade de pacotes ARP Requests e ARP Reply
- Nível de Rede
- Quantidade de pacotes IPv4
- Quantidade de pacotes ICMP
- Quantidade de pacotes IPv6
- Quantidade de pacotes ICMPv6
- Nível de Transporte
- Quantidade de pacotes UDP
- Quantidade de pacotes TCP

- 
