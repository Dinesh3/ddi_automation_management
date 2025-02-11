from datetime import datetime
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from app import app
import dns.resolver
import threading
import csv
import os

def dns_lookup(dns_name, results, index):
    result = {
        'dns_name': dns_name,
        'target_value': [],
        'cname': 'N/A',
        'fqdn': dns_name,
        'zone_name': 'N/A',
        'soa_record': 'N/A',
        'ns_records': [],
        'ptr_records': [],
        'reverse_lookup': 'N/A'
    }
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2  # Set a shorter timeout

    try:
        # A Record
        a_answers = resolver.resolve(dns_name, 'A')
        result['target_value'] = [rdata.to_text() for rdata in a_answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        result['target_value'] = ['N/A']

    try:
        # CNAME Record
        cname_answers = resolver.resolve(dns_name, 'CNAME')
        result['cname'] = cname_answers[0].to_text()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        result['cname'] = 'N/A'
    
    try:
        # SOA Record
        soa_answers = resolver.resolve(dns_name, 'SOA')
        result['soa_record'] = soa_answers[0].to_text()
        result['zone_name'] = soa_answers[0].mname.to_text()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        result['soa_record'] = 'N/A'
        result['zone_name'] = 'N/A'
    
    try:
        # NS Records
        ns_answers = resolver.resolve(dns_name, 'NS')
        result['ns_records'] = [rdata.to_text() for rdata in ns_answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        result['ns_records'] = ['N/A']
    
    try:
        # PTR Records
        ptr_answers = resolver.resolve(dns_name, 'PTR')
        result['ptr_records'] = [rdata.to_text() for rdata in ptr_answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        result['ptr_records'] = ['N/A']
    
    # Reverse Lookup
    try:
        reverse_lookup_answers = resolver.resolve(result['target_value'][0], 'PTR')
        result['reverse_lookup'] = reverse_lookup_answers[0].to_text()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, IndexError):
        result['reverse_lookup'] = 'N/A'
    
    results[index] = result

@app.route('/')
def about_us():
    return render_template('about_us.html')

@app.route('/new_request', methods=['GET', 'POST'])
def new_request():
    if request.method == 'POST':
        if 'validate' in request.form:
            dns_name = request.form['dns_name']
            try:
                dns.resolver.resolve(dns_name, 'A')
                flash(f"DNS record for {dns_name} already exists.")
            except dns.resolver.NXDOMAIN:
                flash(f"DNS record for {dns_name} does not exist.")
            return redirect(url_for('new_request'))
        
        elif 'submit' in request.form:
            dns_type = request.form['dns_type']
            action = request.form['action']
            dns_name = request.form['dns_name']
            target_value = request.form['target_value']
            
            current_time_stamp = datetime.now()
            # Store request in CSV file
            with open(f'data/{current_time_stamp}requests.csv', 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([dns_type, action, dns_name, target_value])
            
            flash(f"Request submitted successfully!")
            return redirect(url_for('new_request'))
    
    return render_template('new_request.html')

@app.route('/bulk_request', methods=['GET', 'POST'])
def bulk_request():
    if request.method == 'POST':
        bulk_data = request.form['bulk_data']
        # Parse and process bulk data
        # Perform DNS lookups and handle requests
        return jsonify({'message': 'Bulk request processed'})
    
    return render_template('bulk_request.html')

@app.route('/bulk_dns_validation', methods=['GET', 'POST'])
def bulk_dns_validation():
    results = []
    if request.method == 'POST':
        dns_names = request.form['dns_names'].splitlines()
        results = [None] * len(dns_names)
        threads = []
        for index, dns_name in enumerate(dns_names):
            thread = threading.Thread(target=dns_lookup, args=(dns_name, results, index))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
    
    return render_template('bulk_dns_validation.html', results=results)

@app.route('/check_dns', methods=['POST'])
def check_dns():
    dns_name = request.form['dns_name']
    try:
        dns.resolver.resolve(dns_name, 'A')
        return jsonify({'exists': True})
    except dns.resolver.NXDOMAIN:
        return jsonify({'exists': False})
    except dns.resolver.LifetimeTimeout:
        print("timed out, try again later maybe?")
        return jsonify({'exists': False})

