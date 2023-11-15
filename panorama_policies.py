import csv
import os
import sys
import datetime

"""
How to use me:

First, double check that the inventory dictionary is updated / correct.
There may be new firewalls in Panorama that we don't have in this file or
Old firewalls that have been renamed / removed.

1. In Panorama / Firewall, look at a policy and make sure you can see the rule usage column.
    There are at least three options will show:
        Used
        Unused
        Partially Used

2. Click on that.
3. On the Rule Usage pop up, click on PDF/CSV to export the stats.
4. In the File Name box, just replace the text with f (or update the file below)
5. Export it to Downloads which is the default (or update the path below.)
6. Run this python file
    a. It will ask you for the policy name so it can write some command syntax for you, 
    which is not to say it will be 100% correct, this is written to only start you off
    with the /shared pre-rulebase/ context, but we give you a show command so you can go 
    find and update the text file that is written.

7. Then you can take those commands and dump it in Panorama and make changes quickly

This makes decisions for you if the policy hit count is zero 
or if the number of days since a policy has been used is greater than 90.

8. The syntax this gives you the policy name, and allows you to target into the policy 
    -ONLY- those firewalls that have used this policy in < 90 days

This file will do you a solid and delete f.csv from your Downloads folder so you don't have to
and makes it quicker to process each file.

"""


folder = os.path.expanduser('~\\Downloads')
file = 'f.csv'
full_path = os.path.join(folder, file)

inventory = {"my-frwl-01":"0123456789",
            "my-frwl-02":"98765643210"}

firewalls = []
now = datetime.datetime.now()
with open(full_path) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        # ignore row 1
        if line_count == 0:
            line_count += 1
            pass
        else:
            # firewall names
            if row[2] == '0' or row[2] == '-':
                pass
            else:
                # the firewall name has /vsys1 in, and we don't care about that so we slice it
                firewalls.append(row[1][:-6].lower())
            # Capture last hit date
            last_hit_date = row[3]
            # if there isn't one, it comes over as a hyphen
            if last_hit_date != '-':
                # format the date time so we can compare
                last_hit = datetime.datetime.strptime(last_hit_date, "%Y-%m-%d %H:%M:%S") # 2022-10-10 14:43:49
                # define the days based on subtracting today (now) from the last hit date
                days = (now - last_hit).days
                # If the policy in question hasn't been used in 91+ days, we remove the firewall 
                # from the firewall list so we don't keep it in the policy.
                if days > 90:
                    # print(row[1][:-6])
                    try:
                        firewalls.remove(row[1][:-6].lower())
                    except ValueError:
                        None

# if there are no firewalls in the list, then the policy needs to be disabled since it's not in use.
if len(firewalls) == 0:
    print('\n\n[!]\tThis Policy is UNUSED, please DISABLE IT\n\n')
    print(f'[!]\tExiting\t{now}\n\n')
    os.remove(full_path)
    sys.exit()

# write out a list of the firewalls into the text file.
# this is helpful to validate the number of firewalls that are configured onto the policy.
with open(folder + '\\firewalls.txt', 'w') as file:
    for fw in firewalls:
        print(fw, inventory.get(fw))
        file.write(f'{fw}\n')
    file.write("Number of firewalls for this policy:", len(firewalls))

# write out some CLI syntax for you to use via CLI in Panorama.
# remember that we are assuming 'shared pre-rulebase' context policies 
# but you may have to change it to post-rulebase or change from shared Device Group
# to the name of your device group.  Use the show | match command we give you to make sure.
# This will also be visible in the Device Group drop down in Panorama.
with open(folder + '\\firewalls.txt', 'a') as file:
    file.write('\n\n\n')
    policy_name = input("\n\n[?]\tPolicy Name: ")
    show = f'show | match "{policy_name}"\n'
    pol1 = f'delete shared pre-rulebase security rules "{policy_name}" target\n'
    pol2 = f'set shared pre-rulebase security rules "{policy_name}" target negate no\n'
    
    file.write(show)
    file.write('\n')
    file.write(pol1)
    file.write(pol2)
    
    for fw in firewalls:
        sn = inventory.get(fw)
        pol3 = f'set shared pre-rulebase security rules "{policy_name}" target devices {sn}\n'
        file.write(pol3)
    
os.remove(full_path)

print(f'[i]\tDone\t{now}\n\n')
