from tkinter import *
from PIL import ImageTk,Image
from tkinter.ttk import *
import tkinter.font as font
import _thread
import socket
import struct
middle_frame=None

class EPkts:
	def __init__(self,src,dest,ptl,data):
		self.src=src
		self.dest=dest
		self.ptl=ptl
		self.data=data
class IPPkts:
	def __init__(self,version,hlen,ttl,pt,src,tgt,data):
		self.version=version
		self.header_length=hlen
		self.time_to_live=ttl
		self.protocol=pt
		self.src=src
		self.tgt=tgt
		self.data=data
			
all_ethernet_frames=[]
all_ip_packets=[]
def byte_toMAC_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    return ':'.join(byte_str).upper()
def to_ipv4_addr(addr):
        return '.'.join(map(str, addr))
class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data

def TCPSeg(raw_data):
	(sp, dp, seq, ack, off_res_flags) = struct.unpack('! H H L L H', raw_data[:14])
	offset = (off_res_flags >> 12) * 4
	furg = (off_res_flags & 32) >> 5
	fack = (off_res_flags & 16) >> 4
	fpsh = (off_res_flags & 8) >> 3
	frst = (off_res_flags & 4) >> 2
	fsyn = (off_res_flags & 2) >> 1
	ffin = off_res_flags & 1
	data = raw_data[offset:]
	return sp, dp, seq, ack,furg,fack,fpsh,frst,fsyn,ffin,offset,data

class UDP:

    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]




def packet_sniffer_thread():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		raw_data, addr = conn.recvfrom(65535)
		dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
		destination_mac = byte_toMAC_addr(dest)
		source_mac = byte_toMAC_addr(src)
		underlying_protocol = socket.htons(prototype)
		data = raw_data[14:]
		_list = middle_frame.winfo_children()

		for item in _list:
			if item.winfo_children():
				_list.extend(item.winfo_children())
		print(_list)
		all_ethernet_frames.append(EPkts(source_mac,destination_mac,underlying_protocol,data))
		_list[0].insert('',1,text="",value=(source_mac,destination_mac,underlying_protocol,data))
		print('\n\n\nRECIEVED ETHERNET FRAME')
		print('--Source MAC Address ('+source_mac +') Destination MAC Address ('+ destination_mac+') Protocol: ('+str(underlying_protocol)+')')

		# IPv4 Pfzackets
		if underlying_protocol == 8:
			vhl = data[0]
			version = vhl >> 4
			header_len = (vhl & 15) * 4
			ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
			src = to_ipv4_addr(src)
			target = to_ipv4_addr(target)
			data = data[header_len:]
			_list = middle_frame.winfo_children()

			for item in _list:
				if item.winfo_children():
					_list.extend(item.winfo_children())
		
			all_ip_packets.append(IPPkts(str(version),str(header_len),str(ttl),str(proto),str(src),str(target),data))
			_list[0].insert('',1,text=str(len(all_ip_packets)),value=(str(version),str(header_len),str(ttl),str(proto),str(src),str(target)))
			
			print('--IP PACKET')
			print("----Version: "+str(version)+" Header Length: "+ str(header_len) +" TTL: "+str(ttl))
			print('----Protocol: '+str(proto)+' Source: '+str(src)+' Target: '+str(target))
			# ICMP
			if proto == 1:
				
				typ, code, checksum = struct.unpack('! B B H', data[:4])
				data = data[4:]

				print('--ICMP PACKET'+'\n' + '----Type: ('+str(typ)+') Code: ('+str(code)+")")
				#+' Checksum: '+str(checksum)
				print('----ICMP Data:')
				print(data)
			# TCP
			elif proto == 6:
				src_port, dest_port, sequence, acknowledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,offset,data=TCPSeg(data)

				print('--TCP SEGMENT')
				print('----Source Port: ('+str(src_port)+') Destination Port: ('+ str(dest_port)+')\n'+ '----Sequence: ('+str(sequence)+') Acknowledgment: ('+str(acknowledgment)+")")
				print( '----Flags:')
				print('------((URG:'+str(flag_urg)+ 'ACK: '+str(flag_ack)+'PSH:'+str(flag_psh)+'\n'+'------SYN: '+str(flag_syn)+'RST: '+str(flag_rst)+'FIN:'+str(flag_fin)+"))")
				if len(data) > 0:
					# HTTP
					if src_port == 80 or dest_port == 80:
						print("----" + 'HTTP Data:')
						http = HTTP(data)
						print(http.data)
					else:
						print('----TCP Data:')
						print(data)
			# UDP
			elif proto == 17:
				src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
				data = data[8:]
				print('--UDP Segment:')
				print('----Source Port: ('+str(src_port)+') Destination Port: ('+str(dest_port)+ ') Length: ('+str(size))
				print(data)

		    	# Other IPv4
			else:
				print('--Other IPv4 Data:')
				print(data)
				#print(format_multi_line(DATA_TAB_2, ipv4.data))
		else:
			print('Ethernet Data:')
			print(data)
			#print(format_multi_line(DATA_TAB_1, eth.data))


def OnDoubleClick(event):
    item = ip_tree.selection()
    print('item:', item)
    print('event:', event)
    item = ip_tree.selection()[0]
    print('clicked on', ip_tree.item(item)['text'])
    index=int(ip_tree.item(item)['text'])
    ptl=all_ip_packets[index-1].protocol
    data=all_ip_packets[index-1].data
    if ptl == "1":
        typ, code, checksum = struct.unpack('! B B H', data[:4])
        data = data[4:]
        top=Toplevel()
        top.title("Packet Information")
        top.geometry("300x300")
        label=Label(top,text="ICMP Packet\nType:"+str(typ)+"\nCode:"+str(code)+"\nChecksum:"+str(checksum)+"\nData:"+data)
        label.pack()
    elif ptl == "6":
        src_port, dest_port, sequence, acknowledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,offset,data=TCPSeg(data)
        top=Toplevel()
        top.title("Packet Information")
        top.geometry("300x300")
        txt_str="TCP Segment\nSourcePort:"+str(src_port)+"\nDestination Port:"+str(dest_port)+"\nSequence Number"+str(sequence)+"\nAcknowledgment"+str(acknowledgment)+"\n"
        txt_str+='((URG:'+str(flag_urg)+ 'ACK: '+str(flag_ack)+'PSH:'+str(flag_psh)+'\n'+'------SYN: '+str(flag_syn)+'RST: '+str(flag_rst)+'FIN:'+str(flag_fin)+"))"
        label=Label(top,text=txt_str)
        label.pack()
        
        # HTTP
            
			# UDP
    elif ptl == "17":
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        data = data[8:]
        txt_str="UDP Segment\n"+'----Source Port: ('+str(src_port)+') \nDestination Port: ('+str(dest_port)+ ')\n Length: ('+str(size)
        top=Toplevel()
        top.title("Packet Information")
        top.geometry("300x300")
        label=Label(top,text=txt_str)
        label.pack()
        
    
    

#    print("you clicked on", ip_tree.item(item,"text"))
def mac_layer_btn():
    print("as1")
    #mid_frame=fame_packet_display
    #global middle_frame
    #middle_frame.destroy()
    fame_packet_display = Frame(root, width=600, height=400)
    treeview = Treeview(fame_packet_display)
    treeview['columns'] = ("sm", "dm", "ptl", "d_ip")
    treeview.column("#0", width=30, minwidth=20)
    treeview.column("sm", width=150, minwidth=80, stretch="NO")
    treeview.column("dm", width=150, minwidth=80)
    treeview.column("ptl", width=100, minwidth=80)
    treeview.column("d_ip", width=200, minwidth=180)

    treeview.heading("#0", text="#")
    treeview.heading("sm", text="Sender MAC")
    treeview.heading("dm", text="Destination MAC")
    treeview.heading("ptl", text="Protocol")
    treeview.heading("d_ip", text="Data IP Layer")
    treeview.config(height=17)

#    r1=treeview.insert("",1,text="r1",values=("a\nb","b","b","c"))
#    r2 = treeview.insert("", 2, text="r2", values=("a\nb", "b", "b", "c"))

    i=1
    for item in all_ethernet_frames:
        r1=treeview.insert("",i,text="",values=(item.src,item.dest,item.ptl,item.data))
        i+=1

    treeview.grid(row=0, column=0, padx=15, pady=0, sticky="nsew")

    # photo = ImageTk.PhotoImage(Image.open("11110.png"))
    # labimg = Label(frame_header, image=photo)
    # labimg.image = photo
    # labimg.place(x=0,y=0,relwidth=1, relheight=1)
    # labimg.grid(row=0,column=1)

    yscrollbar = Scrollbar(fame_packet_display, orient='vertical', command=treeview.yview)
    yscrollbar.grid(row=0, column=1, sticky='nse', pady=10)
    treeview.configure(yscrollcommand=yscrollbar.set)
    yscrollbar.configure(command=treeview.yview)

    middle_frame=fame_packet_display
    middle_frame.grid(row=2, column=0, sticky='ews', padx=10, pady=10)

def ip_layer_btn():
	print("as")
    #mid_frame=ip_packet_frame
#    fame_packet_display.destroy()
	#global middle_frame
	#middle_frame.destroy()
	global ip_tree
	ip_packet_frame = Frame(root, width=600, height=400)

	ip_tree = Treeview(ip_packet_frame)
	
	ip_tree['columns'] = ("version", "hlen", "ttl", "ptcl","src","target")
	ip_tree.column("#0", width=30, minwidth=20)
	ip_tree.column("version", width=50, minwidth=50, stretch="NO")
	ip_tree.column("hlen", width=80, minwidth=50)
	ip_tree.column("ttl", width=80, minwidth=50)
	ip_tree.column("ptcl", width=80, minwidth=50)

	ip_tree.column("src", width=150, minwidth=150)
	ip_tree.column("target", width=150, minwidth=150)


	ip_tree.heading("#0", text="#")
	ip_tree.heading("version", text="Version")
	ip_tree.heading("hlen", text="Header Len")
	ip_tree.heading("ttl", text="TTL")
	ip_tree.heading("ptcl", text="Protocol")
	ip_tree.heading("src", text="Src IP")
	ip_tree.heading("target", text="Target IP")
	i=1
	for item in all_ip_packets:
		r1=ip_tree.insert("",i,text=str(i),values=(item.version,item.header_length,item.time_to_live,item.protocol,item.src,item.tgt))
		i+=1
	ip_tree.bind("<<TreeviewSelect>>", OnDoubleClick)
	ip_tree.config(height=17)
	ip_tree.grid(row=0, column=0, padx=15, pady=0, sticky="nsew")

	yscrollbar = Scrollbar(ip_packet_frame, orient='vertical', command=ip_tree.yview)
	yscrollbar.grid(row=0, column=1, sticky='nse', pady=10)
	ip_tree.configure(yscrollcommand=yscrollbar.set)
	yscrollbar.configure(command=ip_tree.yview)

	middle_frame=ip_packet_frame
	middle_frame.grid(row=2, column=0, sticky='ews', padx=10, pady=10)


root=Tk()
#root.iconbitmap("./pkt.ico")
#root.configure(background="#ffffff")
root.title("P-Sniffer")
root.geometry("700x600")
root.resizable(0, 0)


myFont = font.Font(family="Microsoft YaHei",size=30)
myFont1 = font.Font(family="Microsoft YaHei",size=10)

frame_header=Frame(root)
label=Label(frame_header,text="Packet Sniffer")
label['font']=myFont
label.grid(row=0,column=0,padx=15,pady=5,sticky='w')
label1=Label(frame_header,text="Scan all the packets flowing across the network",foreground="#2E86C1")
label1['font']=myFont1
label1.grid(row=1,column=0,padx=15,pady=0)

frame_btns=Frame(root)

button = Button(frame_btns, text="",command=mac_layer_btn)
img = ImageTk.PhotoImage(Image.open("btn_mlp.PNG")) # make sure to add "/" not "\"
button.config(image=img)
button.grid(row=0,column=0,sticky="w") # Dispslaying the button

button2 = Button(frame_btns, text="",command=ip_layer_btn)
img2 = ImageTk.PhotoImage(Image.open("btn_ilp.PNG")) # make sure to add "/" not "\"
button2.config(image=img2)
button2.grid(row=0,column=1,sticky="w") # Displaying the button


fame_packet_display=Frame(root,width=600,height=400)
treeview=Treeview(fame_packet_display)
treeview['columns']=("sm","dm","ptl","d_ip")
treeview.column("#0",width=30,minwidth=20)
treeview.column("sm",width=150,minwidth=80,stretch="NO")
treeview.column("dm",width=150,minwidth=80)
treeview.column("ptl",width=100,minwidth=80)
treeview.column("d_ip",width=200,minwidth=180)


treeview.heading("#0",text="#")
treeview.heading("sm",text="Sender MAC")
treeview.heading("dm",text="Destination MAC")
treeview.heading("ptl",text="Protocol")
treeview.heading("d_ip",text="Data IP Layer")
treeview.config(height=17)
treeview.grid(row=0,column=0,padx=15,pady=0,sticky="nsew")

yscrollbar = Scrollbar(fame_packet_display, orient='vertical', command=treeview.yview)
yscrollbar.grid(row=0, column=1, sticky='nse',pady=10)
treeview.configure(yscrollcommand=yscrollbar.set)
yscrollbar.configure(command=treeview.yview)

middle_frame=fame_packet_display

frame_header.grid(row=0,column=0,sticky='ew',padx=10,pady=0)
frame_btns.grid(row=1,column=0,sticky="w",padx=25,pady=5)
middle_frame.grid(row=2,column=0,sticky='ews',padx=10,pady=10)

_list = middle_frame.winfo_children()

for item in _list:
    if item.winfo_children():
        _list.extend(item.winfo_children())
#_list[0].insert('',1,text="r1",value=("a","b","c","d"))


n_frr=Frame(root,height=100)

l_sp=Label(n_frr,text="Sniffing packets",foreground="#9DA2A5")
l_sp['font']=myFont1
l_sp.grid(row=0,column=0)
lphoto = ImageTk.PhotoImage(Image.open("loading.ico").resize((25, 25),Image.ANTIALIAS))
loaderimg = Label(n_frr, image=lphoto,text="")
loaderimg.image = lphoto
loaderimg.grid(row=0,column=1)

p_inf=Label(n_frr,text="No new packets",foreground="#9DA2A5")
p_inf['font']=myFont1
p_inf.grid(row=1,column=0)

n_p = ImageTk.PhotoImage(Image.open("m1.png").resize((25, 25),Image.ANTIALIAS))
label_np = Label(n_frr, image=n_p,text="")
label_np.image = n_p
label_np.grid(row=1,column=1)

n_frr.grid(row=3,column=0,sticky="w",padx=25)
_thread.start_new_thread(packet_sniffer_thread, ())
root.mainloop()
