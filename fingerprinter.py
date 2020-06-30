##### Homework 4 ####
# Put the test file under tests and then use the command
# Python fingerprinter.py ./tests/xxx.pcap

from scapy.all import *
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
import sys
import os.path
web_list = {'1':'canvas', '2':'bing', '3':'tor', '4':'wikipedia',
            '5':'neverssl', '6':'craigslist', '7':'autolab'}

def read_pcap(file):
    pcaps = rdpcap(file)

    out_addr = None
    out_packets = 0
    in_packets = 0
    total_packets = 0
    in_size = 0
    pcap_data = []

    for packet in pcaps:

        src = packet['IP'].src

        # The first packet is outgoing
        if total_packets == 0:
            out_addr = src
            out_packets += 1
        # This is an outgoing packet
        elif out_addr == src:
            out_packets += 1
        # This is an incoming packet
        else:
            in_packets += 1
            in_size += packet.len
        total_packets += 1

    ratio = float(in_packets) / (out_packets if out_packets != 0 else 1)

    # The ratio of incoming and outgoing data
    pcap_data.append(ratio)
    # The number of incoming packets
    pcap_data.append(in_packets)
    # The number of outgoing packets
    pcap_data.append(out_packets)
    # The number of total packets
    pcap_data.append(total_packets)
    # The size of total incoming packets
    pcap_data.append(in_size)
    pcap_data.reverse()

    return pcap_data

# Randomize the training data
def randomize_data(x, y):
    for i in range(len(x) - 1):
        rand1 = random.randint(0, (len(x) - 1))
        rand2 = random.randint(0, (len(x) - 1))
        if rand1 != rand2:
            x1 = x[rand1]
            x2 = x[rand2]

            y1 = y[rand1]
            y2 = y[rand2]

            x[rand2] = x1
            x[rand1] = x2

            y[rand2] = y1
            y[rand1] = y2

        return x, y


def train_and_predict(file):

    packet_data, web_names = prepare_data()
    packet_data, web_names = randomize_data(packet_data, web_names)

    training_x = packet_data[:]
    training_y = web_names[:]


    prediction_x = read_pcap(file)

    classifier = KNeighborsClassifier()

    # Train
    classifier = classifier.fit(training_x, training_y)

    # Predict
    prediction = classifier.predict_proba([prediction_x])

    # Sort the index of the predictions
    indexes = sorted(range(len(prediction[0])), key=lambda k: prediction[0][k], reverse=True)

    # Get the output from the dictionary
    for i in indexes:
        print(web_list.get(str(i+1)))

# Prepare data for training
def prepare_data():
    packet_data = []
    web_names = []
    # Get the training data from each .pcap file of each directory
    for k, v in web_list.items():
        for file in os.listdir("./pcaps/{}".format(v)):
            if not os.path.isdir(file):
                full_filename = os.path.join("./pcaps/{}".format(v), file)
                if os.path.splitext(full_filename)[-1] == ".pcap":
                    file_data = read_pcap(full_filename)
                    label = k
                    packet_data.append(file_data)
                    web_names.append(label)
    return packet_data, web_names

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Need a pcap file")
        sys.exit(1)
    elif os.path.exists(sys.argv[1]) == False:
        print("There is no such a file")
        sys.exit(1)
    a, b = prepare_data()
    train_and_predict(sys.argv[1])